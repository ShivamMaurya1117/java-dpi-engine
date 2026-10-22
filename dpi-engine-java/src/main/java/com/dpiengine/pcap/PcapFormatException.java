package com.dpiengine.pcap;

import java.io.IOException;

/** Invalid classic-PCAP metadata, distinct from failures reading the underlying storage. */
public final class PcapFormatException extends IOException {
    public PcapFormatException(String message) { super(message); }
}
