package com.dpiengine.pcap;

import com.dpiengine.Main;
import com.dpiengine.rules.RuleSet;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import static org.junit.jupiter.api.Assertions.*;

class PcapFilteringTest {
    @TempDir Path temp;
    private Path input(long linkType) throws IOException {
        Path input = temp.resolve("input.pcap");
        PcapGlobalHeader header = new PcapGlobalHeader(ByteOrder.BIG_ENDIAN, true, 2, 4, 0, 0, 65535, linkType);
        try (PcapWriter writer = new PcapWriter(input, header)) {
            for (int source : new int[]{0xc0a80102, 0xc0a80103, 0xc0a80102}) {
                byte[] bytes = new byte[57];
                ByteBuffer b = ByteBuffer.wrap(bytes);
                b.putShort(12, (short) 0x0800).put(14, (byte) 0x45).putShort(16, (short) 43);
                b.put(23, (byte) 6).putInt(26, source).putInt(30, 0x08080808);
                b.putShort(34, (short) 60000).putShort(36, (short) 443).put(46, (byte) 0x50);
                writer.writePacket(new CapturedPacket(Instant.ofEpochSecond(123, source & 0xffff), 57, 1500, bytes));
            }
            writer.writePacket(new CapturedPacket(Instant.EPOCH, 1, 5, new byte[]{1})); // Unsupported passes through.
        }
        return input;
    }

    @Test
    void noRulesOutputIsByteIdenticalIncludingUnsupportedPackets() throws IOException {
        Path input = input(1), output = temp.resolve("all.pcap");
        Main.main(new String[]{input.toString(), "--output", output.toString()});
        assertArrayEquals(Files.readAllBytes(input), Files.readAllBytes(output));
        assertEquals(new PcapOutputVerifier.Counts(4, 4, 0), PcapOutputVerifier.verify(input, output, RuleSet.empty()));
    }

    @Test
    void filtersBlockedFlowsAndPreservesAllowedPacketContentsAndOrder() throws IOException {
        Path input = input(1), output = temp.resolve("filtered.pcap");
        Main.main(new String[]{input.toString(), "--block-ip", "192.168.1.2", "--output", output.toString()});
        assertEquals(new PcapOutputVerifier.Counts(4, 2, 2), PcapOutputVerifier.verify(input, output,
                RuleSet.builder().blockIpv4("192.168.1.2").build()));
    }

    @Test
    void unknownLinkLayerPassesThroughWithoutParsing() throws IOException {
        Path input = input(101), output = temp.resolve("raw.pcap");
        Main.main(new String[]{input.toString(), "--demo-rules", "--output", output.toString()});
        assertArrayEquals(Files.readAllBytes(input), Files.readAllBytes(output));
    }

    @Test
    void allBlockedCreatesHeaderOnlyCapture() throws IOException {
        Path input = temp.resolve("one.pcap"), output = temp.resolve("empty.pcap");
        PcapGlobalHeader header = new PcapGlobalHeader(ByteOrder.LITTLE_ENDIAN, false, 2, 4, 0, 0, 65535, 1);
        byte[] bytes = new byte[54];
        ByteBuffer b = ByteBuffer.wrap(bytes);
        b.putShort(12, (short) 0x0800).put(14, (byte) 0x45).putShort(16, (short) 40);
        b.put(23, (byte) 6).putInt(26, 0xc0a80102).putInt(30, 0x08080808);
        b.putShort(34, (short) 60000).putShort(36, (short) 443).put(46, (byte) 0x50);
        try (PcapWriter writer = new PcapWriter(input, header)) {
            writer.writePacket(new CapturedPacket(Instant.EPOCH, 54, 54, bytes));
        }
        Main.main(new String[]{input.toString(), "--block-ip", "192.168.1.2", "--output", output.toString()});
        assertEquals(24, Files.size(output));
        assertEquals(new PcapOutputVerifier.Counts(1, 0, 1), PcapOutputVerifier.verify(input, output,
                RuleSet.builder().blockIpv4("192.168.1.2").build()));
    }
}
