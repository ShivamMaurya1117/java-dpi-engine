package com.dpiengine.packet;

import com.dpiengine.pcap.CapturedPacket;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import java.nio.ByteBuffer;
import java.time.Instant;
import java.util.Arrays;
import java.util.Optional;
import static org.junit.jupiter.api.Assertions.*;

class PacketParserTest {
    private final PacketParser parser = new PacketParser();
    private static final Instant TIME = Instant.ofEpochSecond(123, 456000);

    private byte[] frame(int protocol, int ipWords, int tcpWords, int payloadLength, int padding) {
        int transportLength = protocol == 6 ? tcpWords * 4 : 8;
        int total = ipWords * 4 + transportLength + payloadLength;
        byte[] data = new byte[14 + total + padding];
        ByteBuffer b = ByteBuffer.wrap(data);
        b.put(new byte[]{0, 1, 2, 3, 4, 5, (byte) 0xaa, (byte) 0xbb,
                (byte) 0xcc, (byte) 0xdd, (byte) 0xee, (byte) 0xff});
        b.putShort((short) 0x0800);
        b.put(14, (byte) (0x40 | ipWords));
        b.putShort(16, (short) total);
        b.putShort(20, (short) 0x4000); // DF
        b.put(22, (byte) 64).put(23, (byte) protocol);
        b.position(26);
        b.put(new byte[]{(byte) 192, (byte) 168, 1, 2, 8, 8, 8, 8});
        int transport = 14 + ipWords * 4;
        b.putShort(transport, (short) 60000).putShort(transport + 2, (short) 443);
        if (protocol == 6) {
            b.putInt(transport + 4, -1).putInt(transport + 8, 0x80000000);
            b.put(transport + 12, (byte) ((tcpWords << 4) | 1));
            b.put(transport + 13, (byte) 0x12);
        } else {
            b.putShort(transport + 4, (short) (8 + payloadLength));
        }
        Arrays.fill(data, transport + transportLength, 14 + total, (byte) 0x7a);
        return data;
    }

    private Optional<ParsedPacket> parse(byte[] data) {
        return parser.parse(new CapturedPacket(TIME, data.length, data.length, data));
    }

    @ParameterizedTest
    @CsvSource({"5,5", "6,8", "15,15"})
    void parsesTcpWithVariableHeaders(int ipWords, int tcpWords) {
        byte[] data = frame(6, ipWords, tcpWords, 3, 12);
        ParsedPacket p = parse(data).orElseThrow();
        assertEquals(TIME, p.timestamp());
        assertEquals("aa:bb:cc:dd:ee:ff", p.sourceMac());
        assertEquals("00:01:02:03:04:05", p.destinationMac());
        assertEquals(0x0800, p.etherType());
        assertEquals("192.168.1.2", p.sourceIp());
        assertEquals("8.8.8.8", p.destinationIp());
        assertEquals(60000, p.sourcePort());
        assertEquals(443, p.destinationPort());
        assertEquals(6, p.protocol());
        assertEquals(64, p.ttl());
        assertTrue(p.isTcp());
        assertFalse(p.isUdp());
        assertEquals(0x112, p.tcpFlags());
        assertEquals(0xffffffffL, p.sequenceNumber());
        assertEquals(0x80000000L, p.acknowledgmentNumber());
        assertEquals(ipWords * 4, p.ipHeaderLength());
        assertEquals(14 + ipWords * 4, p.transportOffset());
        assertEquals(tcpWords * 4, p.transportHeaderLength());
        assertEquals(14 + (ipWords + tcpWords) * 4, p.payloadOffset());
        assertEquals(3, p.payloadLength());
        assertEquals(0x7a, data[p.payloadOffset()]);
    }

    @ParameterizedTest
    @ValueSource(ints = {0, 3})
    void parsesUdpAndExcludesPadding(int payload) {
        ParsedPacket p = parse(frame(17, 6, 5, payload, 20)).orElseThrow();
        assertTrue(p.isUdp());
        assertFalse(p.isTcp());
        assertEquals(60000, p.sourcePort());
        assertEquals(443, p.destinationPort());
        assertEquals(46, p.payloadOffset());
        assertEquals(payload, p.payloadLength());
        assertEquals(8, p.transportHeaderLength());
        assertEquals(0, p.tcpFlags());
    }

    @Test
    void tcpWithoutPayload() {
        assertEquals(0, parse(frame(6, 5, 5, 0, 0)).orElseThrow().payloadLength());
    }

    @Test
    void udpLengthBoundsPayloadWithinIpPacket() {
        byte[] data = frame(17, 5, 5, 10, 0);
        ByteBuffer.wrap(data).putShort(38, (short) 11);
        assertEquals(3, parse(data).orElseThrow().payloadLength());
    }

    @ParameterizedTest
    @CsvSource({"6,5,5", "6,6,8", "17,5,5", "17,15,5"})
    void rejectsEveryTruncation(int protocol, int ipWords, int tcpWords) {
        byte[] data = frame(protocol, ipWords, tcpWords, 3, 0);
        for (int length = 0; length < data.length; length++) {
            assertTrue(parse(Arrays.copyOf(data, length)).isEmpty(), "length " + length);
        }
    }

    @ParameterizedTest
    @CsvSource({"14,101", "14,68", "14,79", "46,64", "46,240"})
    void rejectsInvalidVersionAndHeaderLengths(int offset, int value) {
        byte[] data = frame(6, 5, 5, 0, 0);
        data[offset] = (byte) value;
        assertTrue(parse(data).isEmpty());
    }

    @ParameterizedTest
    @ValueSource(ints = {0, 19, 39, 65535})
    void rejectsInvalidIpTotalLengthsEvenWithEthernetPadding(int length) {
        byte[] data = frame(6, 5, 5, 0, 20);
        ByteBuffer.wrap(data).putShort(16, (short) length);
        assertTrue(parse(data).isEmpty());
    }

    @Test
    void tcpOptionsCannotExtendIntoEthernetPadding() {
        byte[] data = frame(6, 5, 5, 0, 40);
        data[46] = (byte) 0xf0;
        assertTrue(parse(data).isEmpty());
    }

    @ParameterizedTest
    @ValueSource(ints = {0, 7, 12, 65535})
    void rejectsInvalidUdpLengths(int length) {
        byte[] data = frame(17, 5, 5, 3, 20);
        ByteBuffer.wrap(data).putShort(38, (short) length);
        assertTrue(parse(data).isEmpty());
    }

    @Test
    void transportMinimumMustFitIpLength() {
        for (int protocol : new int[]{6, 17}) {
            byte[] data = frame(protocol, 5, 5, 0, 0);
            ByteBuffer.wrap(data).putShort(16, (short) 24);
            assertTrue(parse(data).isEmpty());
        }
    }

    @ParameterizedTest
    @ValueSource(ints = {0x2000, 1, 0x2001, 0x8000})
    void rejectsFragmentsAndReservedIpFlag(int flags) {
        byte[] data = frame(6, 5, 5, 0, 0);
        ByteBuffer.wrap(data).putShort(20, (short) flags);
        assertTrue(parse(data).isEmpty());
    }

    @ParameterizedTest
    @ValueSource(ints = {0x86dd, 0x0806, 0x8100, 100})
    void skipsUnsupportedEtherTypesAndIeee8023(int etherType) {
        byte[] data = frame(6, 5, 5, 0, 0);
        ByteBuffer.wrap(data).putShort(12, (short) etherType);
        assertTrue(parse(data).isEmpty());
    }

    @ParameterizedTest
    @ValueSource(ints = {1, 0, 47, 255})
    void skipsUnsupportedIpProtocols(int protocol) {
        byte[] data = frame(6, 5, 5, 0, 0);
        data[23] = (byte) protocol;
        assertTrue(parse(data).isEmpty());
    }
}
