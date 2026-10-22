package com.dpiengine.inspect;

import com.dpiengine.pcap.CapturedPacket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Instant;

final class InspectionFixtures {
    static byte[] ascii(String value) { return value.getBytes(StandardCharsets.US_ASCII); }

    static byte[] tls(String name) {
        byte[] host = ascii(name);
        int bodyLength = 52 + host.length;
        ByteBuffer b = ByteBuffer.allocate(9 + bodyLength);
        b.put((byte) 22).putShort((short) 0x0301).putShort((short) (4 + bodyLength));
        b.put((byte) 1).put((byte) 0).putShort((short) bodyLength);
        b.putShort((short) 0x0303).put(new byte[32]).put((byte) 0);
        b.putShort((short) 2).putShort((short) 0x1301).put((byte) 1).put((byte) 0);
        b.putShort((short) (9 + host.length));
        b.putShort((short) 0).putShort((short) (5 + host.length));
        b.putShort((short) (3 + host.length)).put((byte) 0).putShort((short) host.length).put(host);
        return b.array();
    }

    static byte[] dns(String name) {
        ByteBuffer b = ByteBuffer.allocate(12 + name.length() + 2 + 4);
        b.putShort((short) 123).putShort((short) 0x0100).putShort((short) 1).put(new byte[6]);
        for (String label : name.split("\\.")) b.put((byte) label.length()).put(ascii(label));
        b.put((byte) 0).putShort((short) 1).putShort((short) 1);
        return b.array();
    }

    static byte[] http(String name) { return ascii("GET / HTTP/1.1\r\nHost: " + name + "\r\n\r\n"); }

    static CapturedPacket frame(byte[] payload, int protocol, int source, int destination, boolean reverse) {
        int transport = 38; // IPv4 options exercise ParsedPacket's offsets.
        int headerLength = protocol == 6 ? 24 : 8;
        int payloadOffset = transport + headerLength;
        ByteBuffer b = ByteBuffer.allocate(payloadOffset + payload.length + 12); // Ethernet padding.
        b.putShort(12, (short) 0x0800).put(14, (byte) 0x46);
        b.putShort(16, (short) (24 + headerLength + payload.length));
        b.put(23, (byte) protocol);
        b.putInt(26, reverse ? 0x08080808 : 0xc0a80102).putInt(30, reverse ? 0xc0a80102 : 0x08080808);
        b.putShort(transport, (short) source).putShort(transport + 2, (short) destination);
        if (protocol == 6) b.put(transport + 12, (byte) 0x60);
        else b.putShort(transport + 4, (short) (8 + payload.length));
        b.position(payloadOffset);
        b.put(payload);
        return new CapturedPacket(Instant.parse("2020-01-01T00:00:00Z"), b.capacity(), b.capacity(), b.array());
    }
}
