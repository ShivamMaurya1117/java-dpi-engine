package com.dpiengine.engine;

import com.dpiengine.flow.FlowKey;
import com.dpiengine.flow.FlowState;
import com.dpiengine.pcap.PcapGlobalHeader;
import com.dpiengine.report.ProcessingStats;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/** Returned only after input and output resources close successfully. */
public record DpiProcessingResult(Path inputPath, Path outputPath, PcapGlobalHeader globalHeader,
                                  ProcessingStats stats, Map<FlowKey, FlowState> flows) {
    public DpiProcessingResult {
        Objects.requireNonNull(inputPath);
        Objects.requireNonNull(globalHeader);
        Objects.requireNonNull(stats);
        flows = Map.copyOf(flows);
    }

    public List<FlowState> topFlows(int limit) {
        if (limit < 0) throw new IllegalArgumentException("Limit must not be negative");
        return flows.values().stream()
                .sorted(Comparator.comparingLong(FlowState::packetCount).reversed()
                        .thenComparing(flow -> flow.key().toString()))
                .limit(limit).toList();
    }
}
