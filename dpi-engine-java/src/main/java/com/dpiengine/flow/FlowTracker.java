package com.dpiengine.flow;

import com.dpiengine.packet.ParsedPacket;
import com.dpiengine.pcap.CapturedPacket;
import com.dpiengine.inspect.AppClassifier;
import com.dpiengine.inspect.AppType;
import com.dpiengine.inspect.InspectionResult;
import java.util.EnumMap;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/** Single-threaded directional flow table; retains all observed flows for capture reporting. */
public final class FlowTracker {
    private final HashMap<FlowKey, FlowState> flows = new HashMap<>();
    private final AppClassifier classifier = new AppClassifier();

    /** Counts and inspects the same packet exactly once. */
    public FlowState track(CapturedPacket captured, ParsedPacket packet) {
        return track(captured, packet, classifier.inspect(captured, packet));
    }

    /** Reuses packet inspection when another consumer (such as rules) needs the same result. */
    public FlowState track(CapturedPacket captured, ParsedPacket packet, InspectionResult inspection) {
        return track(packet, captured.capturedLength(), Objects.requireNonNull(inspection));
    }

    /** capturedBytes is the PCAP captured length, including link and transport headers. */
    public FlowState track(ParsedPacket packet, long capturedBytes) {
        return track(packet, capturedBytes, new InspectionResult(classifier.fallback(packet), ""));
    }

    private FlowState track(ParsedPacket packet, long capturedBytes, InspectionResult inspection) {
        Objects.requireNonNull(packet, "packet");
        Objects.requireNonNull(packet.timestamp(), "timestamp");
        if (!packet.isTcp() && !packet.isUdp()) {
            throw new IllegalArgumentException("Only parsed TCP and UDP packets can be tracked");
        }
        if (capturedBytes < 0 || capturedBytes > 0xffffffffL
                || capturedBytes < (long) packet.payloadOffset() + packet.payloadLength()) {
            throw new IllegalArgumentException("Invalid captured byte count");
        }
        FlowKey key = FlowKey.from(packet);
        boolean closed = packet.isTcp() && (packet.tcpFlags() & 0x05) != 0;
        return flows.compute(key, (ignored, previous) -> (previous == null
                ? FlowState.first(key, capturedBytes, packet.timestamp(), closed)
                : previous.update(capturedBytes, packet.timestamp(), closed)).classify(inspection));
    }

    /** Distribution counts final flow classifications, rather than packet observations. */
    public Map<AppType, Long> applicationDistribution() {
        Map<AppType, Long> counts = new EnumMap<>(AppType.class);
        for (FlowState flow : flows.values()) counts.merge(flow.appType(), 1L, Long::sum);
        return Map.copyOf(counts);
    }

    public int uniqueFlowCount() {
        return flows.size();
    }

    public Optional<FlowState> find(FlowKey key) {
        return Optional.ofNullable(flows.get(key));
    }

    /** Stable immutable snapshot; callers cannot change tracker statistics. */
    public Map<FlowKey, FlowState> flows() {
        return Map.copyOf(flows);
    }

    /** Ties are ordered by the printed five-tuple for deterministic reports. */
    public List<FlowState> topFlows(int limit) {
        if (limit < 0) throw new IllegalArgumentException("Limit must not be negative");
        return flows.values().stream()
                .sorted(Comparator.comparingLong(FlowState::packetCount).reversed()
                        .thenComparing(flow -> flow.key().toString()))
                .limit(limit).toList();
    }
}
