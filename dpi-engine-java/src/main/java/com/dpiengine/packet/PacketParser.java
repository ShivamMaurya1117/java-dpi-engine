package com.dpiengine.packet;

import com.dpiengine.pcap.CapturedPacket;
import java.util.HexFormat;
import java.util.Optional;

/** Stateless parser for Ethernet II carrying unfragmented IPv4 TCP/UDP.
 * Unsupported or malformed frames return empty. Checksums are not verified.
 */
public final class PacketParser {
    public static final int TCP = 6;
    public static final int UDP = 17;
    private static final int ETHERNET_LENGTH = 14;
    private static final int IPV4 = 0x0800;

    public Optional<ParsedPacket> parse(CapturedPacket packet) {
        byte[] data = packet.rawBytes();
        if (!contains(data.length, 0, ETHERNET_LENGTH)) return Optional.empty();
        int etherType = u16(data, 12);
        if (etherType != IPV4) return Optional.empty();

        int ip = ETHERNET_LENGTH;
        if (!contains(data.length, ip, 20)) return Optional.empty();
        int version = u8(data, ip) >>> 4;
        int ipLength = (u8(data, ip) & 15) * 4;
        int totalLength = u16(data, ip + 2);
        if (version != 4 || ipLength < 20 || totalLength < ipLength
                || !contains(data.length, ip, totalLength)) return Optional.empty();
        // Reject reserved flag, MF, and any fragment offset; DF alone is supported.
        if ((u16(data, ip + 6) & 0xbfff) != 0) return Optional.empty();
        int protocol = u8(data, ip + 9);
        int end = ip + totalLength;
        int transport = ip + ipLength;
        int transportLength;
        int payloadEnd = end;
        int flags = 0;
        long sequence = 0;
        long acknowledgment = 0;
        if (protocol == TCP) {
            if (!contains(end, transport, 20)) return Optional.empty();
            transportLength = (u8(data, transport + 12) >>> 4) * 4;
            if (transportLength < 20 || !contains(end, transport, transportLength)) return Optional.empty();
            // Include the NS bit from byte 12 alongside the eight flags in byte 13.
            flags = ((u8(data, transport + 12) & 1) << 8) | u8(data, transport + 13);
            sequence = u32(data, transport + 4);
            acknowledgment = u32(data, transport + 8);
        } else if (protocol == UDP) {
            transportLength = 8;
            if (!contains(end, transport, transportLength)) return Optional.empty();
            int udpLength = u16(data, transport + 4);
            if (udpLength < 8 || !contains(end, transport, udpLength)) return Optional.empty();
            payloadEnd = transport + udpLength;
        } else {
            return Optional.empty();
        }
        int payload = transport + transportLength;
        return Optional.of(new ParsedPacket(packet.timestamp(), mac(data, 6), mac(data, 0),
                etherType, ip(data, ip + 12), ip(data, ip + 16), protocol, u8(data, ip + 8),
                u16(data, transport), u16(data, transport + 2), flags, sequence, acknowledgment,
                ipLength, transport, transportLength, payload, payloadEnd - payload));
    }

    private static boolean contains(int end, int offset, int length) {
        return offset >= 0 && offset <= end && length >= 0 && length <= end - offset;
    }

    private static int u8(byte[] data, int offset) { return Byte.toUnsignedInt(data[offset]); }
    private static int u16(byte[] data, int offset) {
        return (u8(data, offset) << 8) | u8(data, offset + 1);
    }
    private static long u32(byte[] data, int offset) {
        return ((long) u16(data, offset) << 16) | u16(data, offset + 2);
    }
    private static String mac(byte[] data, int offset) {
        return HexFormat.ofDelimiter(":").formatHex(data, offset, offset + 6);
    }
    private static String ip(byte[] data, int offset) {
        return u8(data, offset) + "." + u8(data, offset + 1) + "."
                + u8(data, offset + 2) + "." + u8(data, offset + 3);
    }
}
