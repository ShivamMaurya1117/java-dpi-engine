package com.dpiengine.pcap;

import java.time.Instant;

/** Raw captured data; no protocol parsing is performed. */
public record CapturedPacket(Instant timestamp, long capturedLength,
                             long originalLength, byte[] rawBytes) {
    public CapturedPacket {
        rawBytes = rawBytes.clone();
    }

    @Override
    public byte[] rawBytes() {
        return rawBytes.clone();
    }
}
