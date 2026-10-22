package com.dpiengine.engine;

import com.dpiengine.pcap.PcapReader;

/** Optional work budget; the existing standalone engine constructors retain their original limits. */
public record ProcessingLimits(long maxPackets, int maxFlows, int maxPacketBytes) {
    public ProcessingLimits {
        if (maxPackets < 1 || maxFlows < 1 || maxPacketBytes < 1
                || maxPacketBytes > PcapReader.MAX_CAPTURED_LENGTH) {
            throw new IllegalArgumentException("Processing limits must be positive and packet bytes at most 64 MiB");
        }
    }

    public static ProcessingLimits unrestricted() {
        return new ProcessingLimits(Long.MAX_VALUE, Integer.MAX_VALUE, PcapReader.MAX_CAPTURED_LENGTH);
    }
}
