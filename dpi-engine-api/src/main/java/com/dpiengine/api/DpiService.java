package com.dpiengine.api;

import com.dpiengine.engine.DpiEngine;
import com.dpiengine.engine.DpiEngineConfig;
import com.dpiengine.engine.DpiProcessingException;
import com.dpiengine.engine.ProcessingLimits;
import com.dpiengine.engine.ProcessingLimitException;
import com.dpiengine.pcap.PcapReader;
import com.dpiengine.pcap.PcapFormatException;
import com.dpiengine.pcap.PcapLimitException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;
import java.io.IOException;
import java.io.EOFException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.Semaphore;

@Service
public class DpiService {
    private final ApiProperties properties;
    private final Semaphore permits;
    private final Semaphore workerPermits;
    private final ReaderFactory readers;
    @FunctionalInterface interface ReaderFactory { PcapReader open(Path path, int maxBytes) throws IOException; }
    @FunctionalInterface interface Download { void send(Path path, AnalysisResponse stats) throws IOException; }

    @Autowired
    public DpiService(ApiProperties properties) {
        this(properties, PcapReader::new);
    }

    DpiService(ApiProperties properties, ReaderFactory readers) {
        this.properties = properties;
        permits = new Semaphore(properties.maxConcurrentRequests());
        workerPermits = new Semaphore(properties.maxTotalWorkers());
        this.readers = readers;
    }

    AnalysisResponse process(MultipartFile upload, DpiOptions options, Download download) throws IOException {
        if (upload.isEmpty()) throw new ApiFailure(HttpStatus.BAD_REQUEST, "PCAP file must not be empty");
        if (upload.getSize() > properties.maxUploadSize().toBytes()) throw new ApiFailure(HttpStatus.PAYLOAD_TOO_LARGE, "Upload exceeds configured limit");
        var rules = options.rules();
        if (options.workerCount() < 1 || options.workerCount() > 64) throw new IllegalArgumentException("Workers must be between 1 and 64");
        if (options.workerCount() > properties.maxWorkersPerRequest() || options.workerCount() > properties.maxTotalWorkers()) {
            throw new ApiFailure(HttpStatus.BAD_REQUEST, "Requested workers exceed API limit of "
                    + Math.min(properties.maxWorkersPerRequest(), properties.maxTotalWorkers()) + "; request fewer workers");
        }
        if (!permits.tryAcquire()) throw new ApiFailure(HttpStatus.TOO_MANY_REQUESTS, "Concurrent processing limit reached; retry later");
        try {
            if (!workerPermits.tryAcquire(options.workerCount())) {
                throw new ApiFailure(HttpStatus.TOO_MANY_REQUESTS, "Combined worker budget reached; retry later or request fewer workers");
            }
            try {
                Files.createDirectories(properties.tempDirectory());
                try (Workspace workspace = new Workspace(Files.createTempDirectory(properties.tempDirectory(), "request-"))) {
                    upload.transferTo(workspace.input);
                    // Validate the whole classic-PCAP framing before processing or returning a download.
                    try (PcapReader reader = readers.open(workspace.input, properties.maxPacketBytes())) {
                        if (reader.globalHeader().network() != 1) {
                            throw new ApiFailure(HttpStatus.BAD_REQUEST,
                                    "Unsupported PCAP link type " + reader.globalHeader().network()
                                            + "; Ethernet (link type 1, DLT_EN10MB) is required. Upload an Ethernet PCAP capture.");
                        }
                        long records = 0;
                        while (reader.readPacket().isPresent()) {
                            if (++records > properties.maxPackets()) throw new ApiFailure(HttpStatus.PAYLOAD_TOO_LARGE,
                                    "PCAP exceeds record budget of " + properties.maxPackets() + "; split the capture");
                        }
                    } catch (EOFException | PcapFormatException e) {
                        throw new ApiFailure(HttpStatus.BAD_REQUEST, "Invalid, unsupported, or truncated classic PCAP file", e);
                    } catch (PcapLimitException e) {
                        throw new ApiFailure(HttpStatus.PAYLOAD_TOO_LARGE, e.getMessage(), e);
                    }
                    AnalysisResponse stats;
                    try {
                        var limits = new ProcessingLimits(properties.maxPackets(), properties.maxFlows(), properties.maxPacketBytes());
                        var result = new DpiEngine().process(new DpiEngineConfig(workspace.input,
                                download == null ? null : workspace.output, rules, options.workerCount(), 8, limits));
                        stats = AnalysisResponse.from(result.stats());
                    } catch (DpiProcessingException e) {
                        if (e.getCause() instanceof ProcessingLimitException || e.getCause() instanceof PcapLimitException) {
                            throw new ApiFailure(HttpStatus.PAYLOAD_TOO_LARGE, e.getMessage(), e);
                        }
                        throw e;
                    }
                    // Synchronous bounded-memory transfer: retain ownership and admission permits until copying ends.
                    if (download != null) download.send(workspace.output, stats);
                    return stats;
                }
            } finally { workerPermits.release(options.workerCount()); }
        } finally { permits.release(); }
    }
}
