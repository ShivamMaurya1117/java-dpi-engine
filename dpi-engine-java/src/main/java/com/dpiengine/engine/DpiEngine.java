package com.dpiengine.engine;

import com.dpiengine.flow.FlowTracker;
import com.dpiengine.flow.FlowKey;
import com.dpiengine.inspect.AppClassifier;
import com.dpiengine.packet.PacketParser;
import com.dpiengine.packet.ParsedPacket;
import com.dpiengine.pcap.CapturedPacket;
import com.dpiengine.pcap.PcapGlobalHeader;
import com.dpiengine.pcap.PcapReader;
import com.dpiengine.pcap.PcapWriter;
import com.dpiengine.report.ProcessingStats;
import com.dpiengine.rules.BlockReason;
import com.dpiengine.rules.RuleDecision;
import com.dpiengine.rules.RuleEvaluation;
import com.dpiengine.rules.RuleManager;
import java.io.IOException;
import java.nio.file.Path;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/** Reusable single-threaded pipeline. No CLI, console output, or retained state between runs. */
public final class DpiEngine {
    public DpiProcessingResult process(DpiEngineConfig config) throws DpiProcessingException {
        Objects.requireNonNull(config, "config");
        if (config.threads() > 1) return new ParallelDpiEngine().process(config);
        long start = System.nanoTime();
        PacketParser parser = new PacketParser();
        AppClassifier classifier = new AppClassifier();
        FlowTracker tracker = new FlowTracker();
        RuleManager rules = new RuleManager(config.rules());
        Counters counters = new Counters();
        Path outputPath = null;
        PcapGlobalHeader header;
        try (PcapReader reader = new PcapReader(config.inputPath(), config.limits().maxPacketBytes())) {
            header = reader.globalHeader();
            if (config.outputPath() != null) {
                outputPath = PcapWriter.validateOutputPath(config.inputPath(), config.outputPath());
            }
            try (PcapWriter writer = outputPath == null ? null : new PcapWriter(outputPath, header)) {
                Optional<CapturedPacket> next;
                while ((next = reader.readPacket()).isPresent()) {
                    if (counters.total >= config.limits().maxPackets()) throw new ProcessingLimitException(
                            "PCAP exceeds record budget of " + config.limits().maxPackets() + "; split the capture");
                    counters.total++;
                    CapturedPacket captured = next.orElseThrow();
                    RuleEvaluation evaluation = RuleEvaluation.allow();
                    Optional<ParsedPacket> parsed = header.network() == 1 ? parser.parse(captured) : Optional.empty();
                    if (parsed.isPresent()) {
                        ParsedPacket packet = parsed.orElseThrow();
                        if (tracker.uniqueFlowCount() >= config.limits().maxFlows()
                                && tracker.find(FlowKey.from(packet)).isEmpty()) throw new ProcessingLimitException(
                                "PCAP exceeds flow budget of " + config.limits().maxFlows() + "; split the capture");
                        var inspection = classifier.inspect(captured, packet);
                        var flow = tracker.track(captured, packet, inspection);
                        evaluation = rules.evaluate(packet, inspection, flow);
                        counters.parsed++;
                        if (packet.isTcp()) counters.tcp++;
                        if (packet.isUdp()) counters.udp++;
                    }
                    if (evaluation.decision() == RuleDecision.BLOCK) {
                        counters.blocked++;
                        for (BlockReason reason : evaluation.reasons()) counters.reasons.merge(reason, 1L, Long::sum);
                    } else {
                        counters.allowed++;
                        if (writer != null) {
                            writer.writePacket(captured);
                            counters.written++;
                        }
                    }
                }
            }
        } catch (IOException e) {
            throw new DpiProcessingException(e, counters.snapshot(tracker, rules, start), outputPath);
        }
        return new DpiProcessingResult(config.inputPath().toAbsolutePath().normalize(), outputPath, header,
                counters.snapshot(tracker, rules, start), tracker.flows());
    }

    private static final class Counters {
        long total, parsed, tcp, udp, allowed, blocked, written;
        final Map<BlockReason, Long> reasons = new HashMap<>();
        ProcessingStats snapshot(FlowTracker tracker, RuleManager rules, long start) {
            return new ProcessingStats(total, parsed, total - parsed, tcp, udp, tracker.uniqueFlowCount(),
                    tracker.applicationDistribution(), allowed, blocked, written, rules.blockedFlows().size(),
                    reasons, Duration.ofNanos(System.nanoTime() - start));
        }
    }
}
