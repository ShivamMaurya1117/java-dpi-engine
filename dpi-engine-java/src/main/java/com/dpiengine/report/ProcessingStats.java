package com.dpiengine.report;

import com.dpiengine.inspect.AppType;
import com.dpiengine.rules.BlockReason;
import java.time.Duration;
import java.util.Map;
import java.util.Objects;

/** Immutable end-to-end counts. Unsupported packets are included in allowedPackets.
 * Blocking reason counts may overlap. Applications count final directional flows.
 */
public record ProcessingStats(long totalPacketsRead, long successfullyParsedPackets,
                              long skippedPackets, long tcpPackets, long udpPackets,
                              int uniqueFlows, Map<AppType, Long> applicationDistribution,
                              long allowedPackets, long blockedPackets, long writtenPackets,
                              int blockedFlows, Map<BlockReason, Long> blockingReasons,
                              Duration processingDuration) {
    public ProcessingStats {
        applicationDistribution = Map.copyOf(applicationDistribution);
        blockingReasons = Map.copyOf(blockingReasons);
        Objects.requireNonNull(processingDuration, "processingDuration");
    }
}
