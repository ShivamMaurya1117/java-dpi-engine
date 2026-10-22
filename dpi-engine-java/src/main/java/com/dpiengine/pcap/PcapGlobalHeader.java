package com.dpiengine.pcap;

import java.nio.ByteOrder;

/** Classic PCAP metadata. Unsigned 32-bit fields are represented as longs. */
public record PcapGlobalHeader(ByteOrder byteOrder, boolean nanosecondResolution,
                               int versionMajor, int versionMinor, int thisZone,
                               long sigFigs, long snapLength, long network) {
}
