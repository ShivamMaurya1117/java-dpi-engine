package com.dpiengine.engine;

import com.dpiengine.pcap.*;
import com.dpiengine.rules.RuleSet;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Path;
import java.time.Instant;
import static org.junit.jupiter.api.Assertions.*;

class ProcessingLimitsTest {
    @TempDir Path temp;
    private Path capture(int records, int flows, boolean parsed) throws Exception {
        Path path = temp.resolve("input.pcap");
        try (PcapWriter writer = new PcapWriter(path,
                new PcapGlobalHeader(ByteOrder.LITTLE_ENDIAN, false, 2, 4, 0, 0, 65535, 1))) {
            for (int i = 0; i < records; i++) {
                byte[] data = new byte[parsed ? 54 : 0];
                if (parsed) ByteBuffer.wrap(data).putShort(12, (short) 0x0800).put(14, (byte) 0x45)
                        .putShort(16, (short) 40).put(23, (byte) 6).putInt(26, 0xc0a80102)
                        .putInt(30, 0x08080808).putShort(34, (short) (10000 + i % flows))
                        .putShort(36, (short) 443).put(46, (byte) 0x50);
                writer.writePacket(new CapturedPacket(Instant.EPOCH, data.length, data.length, data));
            }
        }
        return path;
    }

    @ParameterizedTest @ValueSource(ints={1, 2, 4, 8})
    void globalFlowLimitRejectsNextDistinctFlowAndClosesOutput(int threads) throws Exception {
        Path input = capture(101, 101, true), output = temp.resolve("output.pcap");
        var config = new DpiEngineConfig(input, output, RuleSet.empty(), threads, 2,
                new ProcessingLimits(200, 100, 64));
        var error = assertThrows(DpiProcessingException.class, () -> new DpiEngine().process(config));
        assertInstanceOf(ProcessingLimitException.class, error.getCause());
        assertTrue(error.getMessage().contains("flow budget of 100"));
        assertTrue(error.partialStats().uniqueFlows() <= 100);
        // Exclusive deletion on Windows also checks that the writer/reader released their handles.
        java.nio.file.Files.delete(output);
        java.nio.file.Files.delete(input);
    }

    @ParameterizedTest @ValueSource(ints={1, 2, 4, 8})
    void repeatedFlowsAtExactLimitRemainValid(int threads) throws Exception {
        Path input = capture(1000, 100, true);
        var result = new DpiEngine().process(new DpiEngineConfig(input, null, RuleSet.empty(), threads, 2,
                new ProcessingLimits(1000, 100, 54)));
        assertEquals(1000, result.stats().totalPacketsRead());
        assertEquals(100, result.stats().uniqueFlows());
    }

    @ParameterizedTest @ValueSource(ints={1, 2, 4, 8})
    void recordBudgetIncludesUnparseableZeroLengthRecords(int threads) throws Exception {
        Path input = capture(11, 1, false);
        var error = assertThrows(DpiProcessingException.class, () -> new DpiEngine().process(
                new DpiEngineConfig(input, null, RuleSet.empty(), threads, 2, new ProcessingLimits(10, 1, 64))));
        assertInstanceOf(ProcessingLimitException.class, error.getCause());
        assertEquals(10, error.partialStats().totalPacketsRead());
        // Original constructor still allows/pass-throughs every unsupported record.
        assertEquals(11, new DpiEngine().process(new DpiEngineConfig(input)).stats().allowedPackets());
    }

    @ParameterizedTest @ValueSource(ints={1, 4})
    void capturedByteBudgetIsEnforcedByReaderBeforeReadingBody(int threads) throws Exception {
        Path input = capture(1, 1, true);
        byte[] bytes = java.nio.file.Files.readAllBytes(input);
        java.nio.file.Files.write(input, java.util.Arrays.copyOf(bytes, 40)); // No body: limit wins before a data read.
        var error = assertThrows(DpiProcessingException.class, () -> new DpiEngine().process(
                new DpiEngineConfig(input, null, RuleSet.empty(), threads, 2, new ProcessingLimits(10, 10, 53))));
        assertInstanceOf(PcapLimitException.class, error.getCause());
    }

    @Test
    void tenThousandFlowBudgetBoundsHighCardinalityCapture() throws Exception {
        Path input = capture(10001, 10001, true);
        var error = assertThrows(DpiProcessingException.class, () -> new DpiEngine().process(
                new DpiEngineConfig(input, null, RuleSet.empty(), 4, 8,
                        new ProcessingLimits(20000, 10000, 54))));
        assertInstanceOf(ProcessingLimitException.class, error.getCause());
        assertTrue(error.getMessage().contains("flow budget of 10000"));
        assertTrue(error.partialStats().uniqueFlows() <= 10000);
        assertTrue(error.partialStats().uniqueFlows() >= 9990);
    }
}
