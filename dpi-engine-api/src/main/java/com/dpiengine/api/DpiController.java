package com.dpiengine.api;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Encoding;
import jakarta.validation.Valid;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import java.io.IOException;
import java.nio.file.Files;

@RestController
@RequestMapping("/api/v1/dpi")
public class DpiController {
    private final DpiService service;
    public DpiController(DpiService service) { this.service = service; }

    @Operation(summary="Analyze a classic PCAP", description="Upload file and optional JSON options. No rules and one worker by default.",
            requestBody=@io.swagger.v3.oas.annotations.parameters.RequestBody(content=@Content(
                    mediaType=MediaType.MULTIPART_FORM_DATA_VALUE,
                    encoding=@Encoding(name="options", contentType=MediaType.APPLICATION_JSON_VALUE))))
    @PostMapping(value="/analyze", consumes=MediaType.MULTIPART_FORM_DATA_VALUE, produces=MediaType.APPLICATION_JSON_VALUE)
    public AnalysisResponse analyze(@RequestPart("file") MultipartFile file,
                                    @Valid @RequestPart(value="options", required=false) DpiOptions options) throws IOException {
        return service.process(file, options == null ? DpiOptions.defaults() : options, null);
    }

    @Operation(summary="Download a filtered classic PCAP", description="Optional JSON options: workers, blockedApplications, blockedDomains, blockedIpv4Addresses. Headers report packet counts.",
            requestBody=@io.swagger.v3.oas.annotations.parameters.RequestBody(content=@Content(
                    mediaType=MediaType.MULTIPART_FORM_DATA_VALUE,
                    encoding=@Encoding(name="options", contentType=MediaType.APPLICATION_JSON_VALUE))))
    @PostMapping(value="/filter", consumes=MediaType.MULTIPART_FORM_DATA_VALUE, produces="application/vnd.tcpdump.pcap")
    @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode="200", description="Filtered PCAP download",
            content=@Content(mediaType="application/vnd.tcpdump.pcap",
                    schema=@io.swagger.v3.oas.annotations.media.Schema(type="string", format="binary")))
    public void filter(@RequestPart("file") MultipartFile file,
                       @Valid @RequestPart(value="options", required=false) DpiOptions options,
                       HttpServletResponse response) throws IOException {
        try {
            service.process(file, options == null ? DpiOptions.defaults() : options, (path, stats) -> {
                response.setContentType("application/vnd.tcpdump.pcap");
                response.setHeader(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"filtered.pcap\"");
                response.setHeader("X-DPI-Total-Packets", Long.toString(stats.totalPackets()));
                response.setHeader("X-DPI-Allowed-Packets", Long.toString(stats.allowedPackets()));
                response.setHeader("X-DPI-Blocked-Packets", Long.toString(stats.blockedPackets()));
                response.setHeader("X-DPI-Unique-Flows", Integer.toString(stats.uniqueFlows()));
                response.setContentLengthLong(Files.size(path));
                Files.copy(path, response.getOutputStream());
            });
        } catch (IOException | RuntimeException e) {
            // Before commitment, remove download headers so the advice can return a JSON problem.
            if (!response.isCommitted()) response.reset();
            throw e;
        }
    }
}
