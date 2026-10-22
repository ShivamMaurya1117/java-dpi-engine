package com.dpiengine.engine;

import com.dpiengine.inspect.AppType;
import com.dpiengine.pcap.CapturedPacket;
import com.dpiengine.pcap.PcapGlobalHeader;
import com.dpiengine.pcap.PcapOutputVerifier;
import com.dpiengine.pcap.PcapWriter;
import com.dpiengine.report.ProcessingStats;
import com.dpiengine.rules.BlockReason;
import com.dpiengine.rules.RuleSet;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Arrays;
import java.util.Map;
import static org.junit.jupiter.api.Assertions.*;

class DpiEngineTest {
    @TempDir Path temp;
    private final DpiEngine engine = new DpiEngine();
    private static final PcapGlobalHeader HEADER = new PcapGlobalHeader(ByteOrder.LITTLE_ENDIAN, false, 2, 4, 0, 0, 65535, 1);

    private CapturedPacket packet(int protocol, boolean reverse, int marker) {
        byte[] data = new byte[protocol == 6 ? 54 : 42];
        ByteBuffer b = ByteBuffer.wrap(data);
        b.putShort(12, (short) 0x0800).put(14, (byte) 0x45).putShort(16, (short) (data.length - 14));
        b.put(23, (byte) protocol);
        int source = protocol == 6 ? 0xc0a80102 : 0xc0a80103;
        b.putInt(26, reverse ? 0x08080808 : source).putInt(30, reverse ? source : 0x08080808);
        b.putShort(34, (short) (reverse ? 443 : 60000)).putShort(36, (short) (reverse ? 60000 : protocol == 6 ? 443 : 53));
        if (protocol == 6) b.put(46, (byte) 0x50);
        else b.putShort(38, (short) 8);
        b.put(0, (byte) marker);
        return new CapturedPacket(Instant.ofEpochSecond(100 + marker), data.length, data.length + 50, data);
    }

    private Path capture(long linkType) throws Exception {
        Path input = temp.resolve("input.pcap");
        PcapGlobalHeader header = new PcapGlobalHeader(HEADER.byteOrder(), false, 2, 4, 0, 0, 65535, linkType);
        try (PcapWriter writer = new PcapWriter(input, header)) {
            writer.writePacket(packet(6, false, 1));
            writer.writePacket(packet(17, false, 2));
            writer.writePacket(packet(6, false, 3));
            writer.writePacket(packet(6, true, 4));
            writer.writePacket(new CapturedPacket(Instant.EPOCH, 1, 5, new byte[]{1}));
        }
        return input;
    }

    private void consistent(DpiProcessingResult result, boolean output) {
        ProcessingStats s = result.stats();
        assertEquals(s.totalPacketsRead(), s.successfullyParsedPackets() + s.skippedPackets());
        assertEquals(s.totalPacketsRead(), s.allowedPackets() + s.blockedPackets());
        assertEquals(s.successfullyParsedPackets(), s.tcpPackets() + s.udpPackets());
        assertEquals(s.uniqueFlows(), result.flows().size());
        assertEquals(s.uniqueFlows(), s.applicationDistribution().values().stream().mapToLong(Long::longValue).sum());
        assertEquals(s.successfullyParsedPackets(), result.flows().values().stream().mapToLong(flow -> flow.packetCount()).sum());
        assertEquals(output ? s.allowedPackets() : 0, s.writtenPackets());
        assertFalse(s.processingDuration().isNegative());
    }

    @Test
    void analysisOnlyReturnsCompleteStatsWithoutCreatingOutput() throws Exception {
        DpiProcessingResult result = engine.process(new DpiEngineConfig(capture(1)));
        consistent(result, false);
        assertNull(result.outputPath());
        assertEquals(5, result.stats().totalPacketsRead());
        assertEquals(4, result.stats().successfullyParsedPackets());
        assertEquals(1, result.stats().skippedPackets());
        assertEquals(3, result.stats().tcpPackets());
        assertEquals(1, result.stats().udpPackets());
        assertEquals(3, result.stats().uniqueFlows());
        assertEquals(5, result.stats().allowedPackets());
        assertEquals(0, result.stats().blockedPackets());
        assertEquals(Map.of(AppType.HTTPS, 2L, AppType.DNS, 1L), result.stats().applicationDistribution());
        assertEquals(2, result.topFlows(1).getFirst().packetCount());
        assertThrows(UnsupportedOperationException.class, () -> result.flows().clear());
        assertThrows(UnsupportedOperationException.class, () -> result.stats().applicationDistribution().clear());
        try (var files = Files.list(temp)) {
            assertEquals(1, files.count());
        }
    }

    @Test
    void outputWithoutRulesPreservesEverythingByteForByte() throws Exception {
        Path input = capture(1), output = temp.resolve("all.pcap");
        DpiProcessingResult result = engine.process(new DpiEngineConfig(input, output, RuleSet.empty()));
        consistent(result, true);
        assertEquals(HEADER, result.globalHeader());
        assertEquals(output, result.outputPath());
        assertArrayEquals(Files.readAllBytes(input), Files.readAllBytes(output));
        assertEquals(new PcapOutputVerifier.Counts(5, 5, 0), PcapOutputVerifier.verify(input, output, RuleSet.empty()));
    }

    @Test
    void customRulesPreserveOrderAndCountPersistentReasons() throws Exception {
        Path input = capture(1), output = temp.resolve("custom.pcap");
        RuleSet rules = RuleSet.builder().blockApplication(AppType.HTTPS).build();
        DpiProcessingResult result = engine.process(new DpiEngineConfig(input, output, rules));
        consistent(result, true);
        assertEquals(3, result.stats().blockedPackets());
        assertEquals(2, result.stats().blockedFlows());
        assertEquals(Map.of(new BlockReason(BlockReason.Type.APPLICATION, "HTTPS"), 3L), result.stats().blockingReasons());
        assertThrows(UnsupportedOperationException.class, () -> result.stats().blockingReasons().clear());
        assertEquals(new PcapOutputVerifier.Counts(5, 2, 3), PcapOutputVerifier.verify(input, output, rules));
    }

    @Test
    void sameEngineStartsEachRunWithFreshState() throws Exception {
        Path input = capture(1);
        RuleSet rules = RuleSet.builder().blockApplication(AppType.HTTPS).build();
        DpiProcessingResult first = engine.process(new DpiEngineConfig(input, null, rules));
        DpiProcessingResult second = engine.process(new DpiEngineConfig(input));
        assertEquals(3, first.stats().blockedPackets());
        assertEquals(0, second.stats().blockedPackets());
        assertEquals(3, second.stats().uniqueFlows());
        assertEquals(first.stats().applicationDistribution(), second.stats().applicationDistribution());
    }

    @Test
    void unsupportedLinkTypeStillCountsAndWritesEveryPacket() throws Exception {
        Path input = capture(101), output = temp.resolve("raw.pcap");
        DpiProcessingResult result = engine.process(new DpiEngineConfig(input, output,
                RuleSet.builder().blockApplication(AppType.UNKNOWN).build()));
        consistent(result, true);
        assertEquals(5, result.stats().skippedPackets());
        assertEquals(0, result.stats().successfullyParsedPackets());
        assertEquals(0, result.stats().uniqueFlows());
        assertArrayEquals(Files.readAllBytes(input), Files.readAllBytes(output));
    }

    @Test
    void emptyCaptureProducesZeroCountsAndValidEmptyOutput() throws Exception {
        Path input = temp.resolve("empty.pcap"), output = temp.resolve("output.pcap");
        try (PcapWriter ignored = new PcapWriter(input, HEADER)) { }
        DpiProcessingResult result = engine.process(new DpiEngineConfig(input, output, RuleSet.empty()));
        consistent(result, true);
        assertEquals(0, result.stats().totalPacketsRead());
        assertEquals(0, result.stats().uniqueFlows());
        assertTrue(result.stats().blockingReasons().isEmpty());
        assertEquals(24, Files.size(output));
    }

    @Test
    void sampleAnalysisAndDemoFilteringMatchVerifiedCaptureContents() throws Exception {
        Path sample = Path.of("../test_dpi.pcap"), output = temp.resolve("demo.pcap");
        DpiProcessingResult analysis = engine.process(new DpiEngineConfig(sample));
        consistent(analysis, false);
        assertEquals(12, analysis.stats().totalPacketsRead());
        assertEquals(12, analysis.stats().successfullyParsedPackets());
        assertEquals(8, analysis.stats().uniqueFlows());
        assertEquals(12, analysis.stats().allowedPackets());
        assertEquals(java.util.Map.of(AppType.HTTP, 2L, AppType.HTTPS, 2L,
                AppType.DNS, 2L, AppType.UNKNOWN, 2L), analysis.stats().applicationDistribution());
        Path unfiltered = temp.resolve("unfiltered.pcap");
        engine.process(new DpiEngineConfig(sample, unfiltered, RuleSet.empty()));
        assertArrayEquals(Files.readAllBytes(sample), Files.readAllBytes(unfiltered));
        RuleSet rules = RuleSet.builder().blockApplication(AppType.DNS).blockDomain("example.org").blockIpv4("203.0.113.99").build();
        DpiProcessingResult filtered = engine.process(new DpiEngineConfig(sample, output, rules));
        consistent(filtered, true);
        assertEquals(6, filtered.stats().allowedPackets());
        assertEquals(6, filtered.stats().blockedPackets());
        assertEquals(5, filtered.stats().blockedFlows());
        assertEquals(2L, filtered.stats().blockingReasons().get(
                new com.dpiengine.rules.BlockReason(com.dpiengine.rules.BlockReason.Type.APPLICATION, "DNS")));
        assertEquals(3L, filtered.stats().blockingReasons().get(
                new com.dpiengine.rules.BlockReason(com.dpiengine.rules.BlockReason.Type.DOMAIN, "example.org")));
        assertEquals(analysis.stats().applicationDistribution(), filtered.stats().applicationDistribution());
        var verified = PcapOutputVerifier.verify(sample, output, rules);
        assertEquals(filtered.stats().writtenPackets(), verified.written());
        assertEquals(filtered.stats().blockedPackets(), verified.blocked());
    }

    @ParameterizedTest
    @ValueSource(ints = {0, 23, 25, 39, 50})
    void truncatedInputThrowsInsteadOfReturningSuccess(int length) throws Exception {
        Path input = capture(1);
        Files.write(input, Arrays.copyOf(Files.readAllBytes(input), length));
        DpiProcessingException error = assertThrows(DpiProcessingException.class,
                () -> engine.process(new DpiEngineConfig(input)));
        assertEquals(0, error.partialStats().totalPacketsRead());
        assertNotNull(error.getCause());
        Files.move(input, temp.resolve("moved.pcap")); // Confirms the reader was closed on failure.
    }

    @Test
    void truncationAfterValidRecordPreservesPartialStatisticsAndClosesOutput() throws Exception {
        Path input = capture(1), output = temp.resolve("partial.pcap");
        Files.write(input, Arrays.copyOf(Files.readAllBytes(input), 24 + 16 + 54 + 10));
        DpiProcessingException error = assertThrows(DpiProcessingException.class,
                () -> engine.process(new DpiEngineConfig(input, output, RuleSet.empty())));
        assertEquals(1, error.partialStats().totalPacketsRead());
        assertEquals(1, error.partialStats().successfullyParsedPackets());
        assertEquals(1, error.partialStats().allowedPackets());
        assertEquals(1, error.partialStats().writtenPackets());
        assertEquals(output, error.outputPath());
        Files.move(output, temp.resolve("moved-output.pcap"));
    }

    @Test
    void malformedGlobalHeaderAndPacketRecordThrow() throws Exception {
        Path input = capture(1);
        byte[] data = Files.readAllBytes(input);
        byte[] invalid = data.clone(); invalid[0] = 0;
        Files.write(input, invalid);
        assertThrows(DpiProcessingException.class, () -> engine.process(new DpiEngineConfig(input)));
        ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN).putInt(24 + 12, 0); // Original length below captured.
        Files.write(input, data);
        assertThrows(DpiProcessingException.class, () -> engine.process(new DpiEngineConfig(input)));
    }

    @Test
    void invalidOutputAndMissingInputDoNotOverwriteExistingFiles() throws Exception {
        Path input = capture(1), existing = temp.resolve("existing.pcap");
        byte[] original = Files.readAllBytes(input);
        Files.write(existing, new byte[]{1, 2, 3});
        for (Path output : new Path[]{input, existing, temp, temp.resolve("missing/file.pcap")}) {
            assertThrows(DpiProcessingException.class, () -> engine.process(new DpiEngineConfig(input, output, RuleSet.empty())));
        }
        assertArrayEquals(original, Files.readAllBytes(input));
        assertArrayEquals(new byte[]{1, 2, 3}, Files.readAllBytes(existing));
        Path output = temp.resolve("never-created.pcap");
        assertThrows(DpiProcessingException.class, () -> engine.process(new DpiEngineConfig(temp.resolve("missing.pcap"), output, RuleSet.empty())));
        assertFalse(Files.exists(output));
    }
}
