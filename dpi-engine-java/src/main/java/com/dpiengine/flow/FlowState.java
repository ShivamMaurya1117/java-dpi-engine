package com.dpiengine.flow;

import java.time.Instant;
import com.dpiengine.inspect.AppType;
import com.dpiengine.inspect.InspectionResult;

/** Immutable statistics snapshot. First/last are the minimum/maximum capture timestamps.
 * CLOSED means a TCP FIN or RST was observed; later packets still contribute statistics.
 */
public record FlowState(FlowKey key, long packetCount, long totalCapturedBytes,
                        Instant firstPacketTimestamp, Instant lastPacketTimestamp,
                        FlowStatus status, AppType appType, String hostname) {
    public FlowState(FlowKey key, long packetCount, long totalCapturedBytes,
                     Instant firstPacketTimestamp, Instant lastPacketTimestamp, FlowStatus status) {
        this(key, packetCount, totalCapturedBytes, firstPacketTimestamp, lastPacketTimestamp,
                status, AppType.UNKNOWN, "");
    }
    static FlowState first(FlowKey key, long capturedBytes, Instant timestamp, boolean closed) {
        return new FlowState(key, 1, capturedBytes, timestamp, timestamp,
                closed ? FlowStatus.CLOSED : FlowStatus.NEW);
    }

    FlowState update(long capturedBytes, Instant timestamp, boolean closed) {
        return new FlowState(key, Math.addExact(packetCount, 1),
                Math.addExact(totalCapturedBytes, capturedBytes),
                timestamp.isBefore(firstPacketTimestamp) ? timestamp : firstPacketTimestamp,
                timestamp.isAfter(lastPacketTimestamp) ? timestamp : lastPacketTimestamp,
                closed || status == FlowStatus.CLOSED ? FlowStatus.CLOSED : FlowStatus.ACTIVE,
                appType, hostname);
    }

    /** First specific application wins; generic classifications remain eligible for upgrades. */
    FlowState classify(InspectionResult result) {
        if (appType.isSpecific()) return this;
        boolean upgrade = result.appType().isSpecific();
        AppType nextType = upgrade || appType == AppType.UNKNOWN
                || !result.hostname().isEmpty() ? result.appType() : appType;
        String nextHost = upgrade || hostname.isEmpty() ? result.hostname() : hostname;
        return new FlowState(key, packetCount, totalCapturedBytes, firstPacketTimestamp,
                lastPacketTimestamp, status, nextType, nextHost);
    }
}
