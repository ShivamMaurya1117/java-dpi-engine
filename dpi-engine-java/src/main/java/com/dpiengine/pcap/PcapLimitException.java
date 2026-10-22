package com.dpiengine.pcap;

import java.io.IOException;

/** A record exceeds the caller's allocation budget, before its data is allocated. */
public final class PcapLimitException extends IOException {
    public PcapLimitException(String message) { super(message); }
}
