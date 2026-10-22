package com.dpiengine.flow;

import com.dpiengine.packet.PacketParser;
import com.dpiengine.packet.ParsedPacket;
import com.dpiengine.pcap.CapturedPacket;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import java.nio.ByteBuffer;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import static org.junit.jupiter.api.Assertions.*;

class FlowTrackerTest {
    private final FlowTracker tracker = new FlowTracker();
    private static final Instant TIME = Instant.parse("2020-01-02T03:04:05.123456789Z");
    private static final FlowKey KEY = new FlowKey("192.168.1.2", "8.8.8.8", 60000, 443, 6);

    private ParsedPacket packet(FlowKey key, Instant time, int flags) {
        boolean tcp = key.protocol() == 6;
        return new ParsedPacket(time, "aa:bb:cc:dd:ee:ff", "00:01:02:03:04:05", 0x0800,
                key.sourceIp(), key.destinationIp(), key.protocol(), 64,
                key.sourcePort(), key.destinationPort(), flags, 0, 0,
                20, 34, tcp ? 20 : 8, tcp ? 54 : 42, 3);
    }

    @Test
    void equalFiveTuplesHaveEqualHashesAndWorkAsMapKeys() {
        FlowKey equal = new FlowKey(new String("192.168.1.2"), new String("8.8.8.8"), 60000, 443, 6);
        assertEquals(KEY, equal);
        assertEquals(KEY.hashCode(), equal.hashCode());
        Map<FlowKey, String> map = new HashMap<>();
        map.put(KEY, "flow");
        assertEquals("flow", map.get(equal));
        assertEquals(KEY, FlowKey.from(packet(KEY, TIME, 0)));
    }

    @Test
    void everyTupleFieldDistinguishesFlows() {
        List<FlowKey> keys = List.of(KEY,
                new FlowKey("192.168.1.3", "8.8.8.8", 60000, 443, 6),
                new FlowKey("192.168.1.2", "8.8.4.4", 60000, 443, 6),
                new FlowKey("192.168.1.2", "8.8.8.8", 60001, 443, 6),
                new FlowKey("192.168.1.2", "8.8.8.8", 60000, 80, 6),
                new FlowKey("192.168.1.2", "8.8.8.8", 60000, 443, 17));
        for (FlowKey key : keys) tracker.track(packet(key, TIME, 0), 100);
        assertEquals(6, tracker.uniqueFlowCount());
        for (FlowState state : tracker.flows().values()) assertEquals(1, state.packetCount());
    }

    @Test
    void identicalTuplesAccumulatePacketsAndCapturedBytes() {
        FlowState first = tracker.track(packet(KEY, TIME, 2), 100);
        FlowState updated = tracker.track(packet(new FlowKey("192.168.1.2", "8.8.8.8", 60000, 443, 6),
                TIME.plusSeconds(1), 16), 200);
        assertEquals(1, tracker.uniqueFlowCount());
        assertEquals(2, updated.packetCount());
        assertEquals(300, updated.totalCapturedBytes());
        assertEquals(FlowStatus.NEW, first.status());
        assertEquals(FlowStatus.ACTIVE, updated.status());
        assertEquals(1, first.packetCount()); // Old snapshot remains stable.
        assertEquals(updated, tracker.find(KEY).orElseThrow());
    }

    @Test
    void captureTimestampsRemainPreciseAndOrderedEvenWhenPacketsAreNot() {
        tracker.track(packet(KEY, TIME, 0), 100);
        tracker.track(packet(KEY, TIME.plusNanos(1), 0), 100);
        tracker.track(packet(KEY, TIME.minusNanos(1), 0), 100);
        tracker.track(packet(KEY, TIME, 0), 100);
        FlowState state = tracker.find(KEY).orElseThrow();
        assertEquals(TIME.minusNanos(1), state.firstPacketTimestamp());
        assertEquals(TIME.plusNanos(1), state.lastPacketTimestamp());
        assertEquals(4, state.packetCount());
    }

    @Test
    void firstPacketSetsBothTimestamps() {
        FlowState state = tracker.track(packet(KEY, TIME, 0), 100);
        assertEquals(TIME, state.firstPacketTimestamp());
        assertEquals(TIME, state.lastPacketTimestamp());
    }

    @Test
    void reverseDirectionRemainsSeparate() {
        FlowKey reverse = new FlowKey(KEY.destinationIp(), KEY.sourceIp(), KEY.destinationPort(), KEY.sourcePort(), 6);
        assertNotEquals(KEY, reverse);
        tracker.track(packet(KEY, TIME, 0), 100);
        assertTrue(tracker.find(reverse).isEmpty());
        tracker.track(packet(reverse, TIME.plusSeconds(2), 0), 80);
        tracker.track(packet(KEY, TIME.plusSeconds(3), 0), 110);
        assertEquals(2, tracker.uniqueFlowCount());
        assertEquals(2, tracker.find(KEY).orElseThrow().packetCount());
        FlowState reverseState = tracker.find(reverse).orElseThrow();
        assertEquals(1, reverseState.packetCount());
        assertEquals(80, reverseState.totalCapturedBytes());
        assertEquals(TIME.plusSeconds(2), reverseState.firstPacketTimestamp());
    }

    @ParameterizedTest
    @ValueSource(ints = {1, 4, 17})
    void tcpFinOrRstClosesButDoesNotLoseLaterStatistics(int flags) {
        assertEquals(FlowStatus.CLOSED, tracker.track(packet(KEY, TIME, flags), 100).status());
        FlowState state = tracker.track(packet(KEY, TIME.plusSeconds(1), 16), 110);
        assertEquals(FlowStatus.CLOSED, state.status());
        assertEquals(2, state.packetCount());
        assertEquals(210, state.totalCapturedBytes());
    }

    @Test
    void activeTcpCanClose() {
        tracker.track(packet(KEY, TIME, 2), 100);
        tracker.track(packet(KEY, TIME, 16), 100);
        assertEquals(FlowStatus.CLOSED, tracker.track(packet(KEY, TIME, 4), 100).status());
    }

    @Test
    void udpBecomesActiveWithoutTcpStatus() {
        FlowKey udp = new FlowKey("192.168.1.2", "8.8.8.8", 50000, 53, 17);
        assertEquals(FlowStatus.NEW, tracker.track(packet(udp, TIME, 0), 60).status());
        assertEquals(FlowStatus.ACTIVE, tracker.track(packet(udp, TIME, 0), 70).status());
        assertEquals(130, tracker.find(udp).orElseThrow().totalCapturedBytes());
    }

    @Test
    void topFiveAreSortedAndLimitedWithDeterministicTies() {
        for (int i = 7; i >= 1; i--) {
            FlowKey key = new FlowKey("192.168.1.2", "8.8.8.8", 60000 + i, 443, 6);
            for (int j = 0; j < i; j++) tracker.track(packet(key, TIME, 0), 100);
        }
        assertEquals(List.of(7L, 6L, 5L, 4L, 3L), tracker.topFlows(5).stream().map(FlowState::packetCount).toList());
        assertEquals(7, tracker.topFlows(20).size());
        assertTrue(tracker.topFlows(0).isEmpty());
        assertThrows(IllegalArgumentException.class, () -> tracker.topFlows(-1));
        FlowTracker ties = new FlowTracker();
        FlowKey second = new FlowKey("192.168.1.2", "8.8.8.8", 60001, 443, 6);
        ties.track(packet(second, TIME, 0), 100);
        ties.track(packet(KEY, TIME, 0), 100);
        assertEquals(List.of(KEY, second), ties.topFlows(5).stream().map(FlowState::key).toList());
    }

    @Test
    void emptyTrackerAndSnapshotsAreSafe() {
        assertEquals(0, tracker.uniqueFlowCount());
        assertTrue(tracker.find(KEY).isEmpty());
        assertTrue(tracker.topFlows(5).isEmpty());
        tracker.track(packet(KEY, TIME, 0), 100);
        Map<FlowKey, FlowState> snapshot = tracker.flows();
        assertThrows(UnsupportedOperationException.class, snapshot::clear);
        assertThrows(UnsupportedOperationException.class, () -> tracker.topFlows(5).clear());
        tracker.track(packet(KEY, TIME, 0), 100);
        assertEquals(1, snapshot.get(KEY).packetCount());
    }

    @ParameterizedTest
    @ValueSource(longs = {-1, 56, 4294967296L})
    void invalidCapturedLengthsDoNotChangeTable(long bytes) {
        assertThrows(IllegalArgumentException.class, () -> tracker.track(packet(KEY, TIME, 0), bytes));
        assertEquals(0, tracker.uniqueFlowCount());
    }

    @Test
    void rejectsUnsupportedProtocol() {
        FlowKey icmp = new FlowKey("192.168.1.2", "8.8.8.8", 0, 0, 1);
        assertThrows(IllegalArgumentException.class, () -> tracker.track(packet(icmp, TIME, 0), 100));
        assertEquals(0, tracker.uniqueFlowCount());
    }

    @Test
    void countsFullCapturedFrameRatherThanOriginalLengthOrPayload() {
        byte[] bytes = new byte[80]; // Includes captured Ethernet padding.
        ByteBuffer b = ByteBuffer.wrap(bytes);
        b.putShort(12, (short) 0x0800).put(14, (byte) 0x45).putShort(16, (short) 43);
        b.put(23, (byte) 6).putInt(26, 0xc0a80102).putInt(30, 0x08080808);
        b.putShort(34, (short) 60000).putShort(36, (short) 443).put(46, (byte) 0x50);
        CapturedPacket captured = new CapturedPacket(TIME, bytes.length, 1500, bytes);
        ParsedPacket parsed = new PacketParser().parse(captured).orElseThrow();
        FlowState state = tracker.track(parsed, captured.capturedLength());
        assertEquals(3, parsed.payloadLength());
        assertEquals(80, state.totalCapturedBytes());
        assertEquals(TIME, state.firstPacketTimestamp());
        assertEquals(KEY, state.key());
    }
}
