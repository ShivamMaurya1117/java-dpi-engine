package com.dpiengine.api;

import com.dpiengine.inspect.AppType;
import com.dpiengine.report.ProcessingStats;
import com.dpiengine.rules.BlockReason;
import java.util.List;
import java.util.Map;

/** JSON adapter for core statistics; structured reasons avoid stringified map keys. */
public record AnalysisResponse(long totalPackets, long parsedPackets, long skippedPackets,
                               long tcpPackets, long udpPackets, int uniqueFlows,
                               Map<AppType, Long> applicationDistribution, long allowedPackets,
                               long blockedPackets, long writtenPackets, int blockedFlows,
                               List<ReasonCount> blockingReasons, double processingDurationMs) {
    public record ReasonCount(BlockReason.Type type, String value, long packets) { }
    public static AnalysisResponse from(ProcessingStats stats) {
        var reasons = stats.blockingReasons().entrySet().stream()
                .sorted(java.util.Comparator.comparing(entry -> entry.getKey().toString()))
                .map(entry -> new ReasonCount(entry.getKey().type(), entry.getKey().value(), entry.getValue())).toList();
        return new AnalysisResponse(stats.totalPacketsRead(), stats.successfullyParsedPackets(), stats.skippedPackets(),
                stats.tcpPackets(), stats.udpPackets(), stats.uniqueFlows(), stats.applicationDistribution(),
                stats.allowedPackets(), stats.blockedPackets(), stats.writtenPackets(), stats.blockedFlows(),
                reasons, stats.processingDuration().toNanos() / 1_000_000.0);
    }
}
