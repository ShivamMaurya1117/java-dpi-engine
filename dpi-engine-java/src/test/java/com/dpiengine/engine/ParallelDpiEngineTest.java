package com.dpiengine.engine;

import com.dpiengine.flow.FlowKey;
import com.dpiengine.inspect.AppType;
import com.dpiengine.pcap.CapturedPacket;
import com.dpiengine.pcap.PcapGlobalHeader;
import com.dpiengine.pcap.PcapOutputVerifier;
import com.dpiengine.pcap.PcapWriter;
import com.dpiengine.report.ProcessingStats;
import com.dpiengine.rules.RuleSet;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.HashSet;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.AbstractExecutorService;
import java.util.List;
import static org.junit.jupiter.api.Assertions.*;

@Timeout(20)
class ParallelDpiEngineTest {
    @TempDir Path temp;
    private static final PcapGlobalHeader HEADER = new PcapGlobalHeader(ByteOrder.LITTLE_ENDIAN, false, 2, 4, 0, 0, 65535, 1);
    private final DpiEngine engine = new DpiEngine();

    private RuleSet demo() {
        return RuleSet.builder().blockApplication(AppType.DNS).blockDomain("example.org").blockIpv4("203.0.113.99").build();
    }
    private void equalResults(DpiProcessingResult baseline, DpiProcessingResult parallel) {
        ProcessingStats a = baseline.stats(), b = parallel.stats();
        assertEquals(a.totalPacketsRead(), b.totalPacketsRead());
        assertEquals(a.successfullyParsedPackets(), b.successfullyParsedPackets());
        assertEquals(a.skippedPackets(), b.skippedPackets());
        assertEquals(a.tcpPackets(), b.tcpPackets());
        assertEquals(a.udpPackets(), b.udpPackets());
        assertEquals(a.uniqueFlows(), b.uniqueFlows());
        assertEquals(a.applicationDistribution(), b.applicationDistribution());
        assertEquals(a.allowedPackets(), b.allowedPackets());
        assertEquals(a.blockedPackets(), b.blockedPackets());
        assertEquals(a.blockedFlows(), b.blockedFlows());
        assertEquals(a.blockingReasons(), b.blockingReasons());
        assertEquals(a.writtenPackets(), b.writtenPackets());
        assertEquals(b.totalPacketsRead(), b.allowedPackets() + b.blockedPackets());
        assertEquals(b.totalPacketsRead(), b.successfullyParsedPackets() + b.skippedPackets());
        assertEquals(baseline.flows(), parallel.flows());
        assertEquals(baseline.topFlows(5), parallel.topFlows(5));
    }

    @ParameterizedTest
    @ValueSource(ints = {2, 4, 8})
    void sampleNoRulesAndDemoAreIdenticalToSequential(int workers) throws Exception {
        Path input = Path.of("../test_dpi.pcap");
        for (RuleSet rules : new RuleSet[]{RuleSet.empty(), demo()}) {
            String label = rules.applications().isEmpty() ? "all" : "demo";
            Path singleOutput = temp.resolve(label + "-single.pcap"), parallelOutput = temp.resolve(label + "-parallel.pcap");
            var single = engine.process(new DpiEngineConfig(input, singleOutput, rules));
            var parallel = engine.process(new DpiEngineConfig(input, parallelOutput, rules, workers, 3));
            equalResults(single, parallel);
            assertEquals(12, parallel.stats().totalPacketsRead());
            assertEquals(8, parallel.stats().uniqueFlows());
            assertArrayEquals(Files.readAllBytes(singleOutput), Files.readAllBytes(parallelOutput));
            assertEquals(parallel.stats().writtenPackets(), PcapOutputVerifier.verify(input, parallelOutput, rules).written());
        }
        equalResults(engine.process(new DpiEngineConfig(input)),
                engine.process(new DpiEngineConfig(input, null, RuleSet.empty(), workers)));
        noWorkersRemain();
    }

    private CapturedPacket packet(int id, int flow) {
        byte[] data = new byte[54];
        ByteBuffer b = ByteBuffer.wrap(data);
        b.putInt(0, id).putShort(12, (short) 0x0800).put(14, (byte) 0x45).putShort(16, (short) 40);
        b.put(23, (byte) 6).putInt(26, 0xc0a80102).putInt(30, 0x08080808);
        b.putShort(34, (short) (10000 + flow)).putShort(36, (short) 443).put(46, (byte) 0x50);
        return new CapturedPacket(Instant.ofEpochSecond(id), data.length, 100, data);
    }
    private Path capture(int packets, int flows) throws Exception {
        Path input = temp.resolve("input.pcap");
        try (PcapWriter writer = new PcapWriter(input, HEADER)) {
            for (int i = 0; i < packets; i++) writer.writePacket(packet(i, i % flows));
        }
        return input;
    }

    @ParameterizedTest
    @ValueSource(ints = {2, 4, 8})
    void manyPacketsInOneFlowMaintainArrivalOrderUnderBackpressure(int workers) throws Exception {
        Path input = capture(3000, 1), single = temp.resolve("single.pcap"), output = temp.resolve("parallel.pcap");
        RuleSet rules = RuleSet.builder().blockApplication(AppType.HTTPS).build();
        equalResults(engine.process(new DpiEngineConfig(input, single, rules)),
                engine.process(new DpiEngineConfig(input, output, rules, workers, 1)));
        assertArrayEquals(Files.readAllBytes(single), Files.readAllBytes(output));
        Map<String, AtomicInteger> threads = new ConcurrentHashMap<>();
        new ParallelDpiEngine(packet -> {
            int id = ByteBuffer.wrap(packet.rawBytes()).getInt();
            int expected = threads.computeIfAbsent(Thread.currentThread().getName(), ignored -> new AtomicInteger()).getAndIncrement();
            if (id != expected) throw new IllegalStateException("Flow processed out of arrival order");
        }).process(new DpiEngineConfig(input, null, RuleSet.empty(), workers, 4));
        assertEquals(1, threads.size());
        assertEquals(3000, threads.values().iterator().next().get());
        noWorkersRemain();
    }

    @ParameterizedTest
    @ValueSource(ints = {2, 4, 8})
    void multipleFlowsUseEveryWorkerAndPreserveAllBytes(int workers) throws Exception {
        Path input = capture(1000, 128), output = temp.resolve("parallel.pcap");
        Map<String, Boolean> used = new ConcurrentHashMap<>();
        var result = new ParallelDpiEngine(packet -> used.put(Thread.currentThread().getName(), true))
                .process(new DpiEngineConfig(input, output, RuleSet.empty(), workers, 8));
        assertEquals(workers, used.size());
        assertEquals(128, result.stats().uniqueFlows());
        assertEquals(1000, result.stats().writtenPackets());
        assertArrayEquals(Files.readAllBytes(input), Files.readAllBytes(output));
        noWorkersRemain();
    }

    @Test
    void emptyCaptureShutsDownCleanly() throws Exception {
        Path input = capture(0, 1), output = temp.resolve("empty.pcap");
        var result = engine.process(new DpiEngineConfig(input, output, RuleSet.empty(), 8, 1));
        assertEquals(0, result.stats().totalPacketsRead());
        assertEquals(0, result.stats().uniqueFlows());
        assertArrayEquals(Files.readAllBytes(input), Files.readAllBytes(output));
        noWorkersRemain();
    }

    @Test
    void slowFirstWorkerBoundsWindowAndOrderedOutput() throws Exception {
        Path input = capture(30, 30), output = temp.resolve("ordered.pcap");
        CountDownLatch firstStarted = new CountDownLatch(1), release = new CountDownLatch(1), secondFinished = new CountDownLatch(1);
        AtomicInteger started = new AtomicInteger();
        var parallel = new ParallelDpiEngine(packet -> {
            started.incrementAndGet();
            if (ByteBuffer.wrap(packet.rawBytes()).getInt() == 0) {
                firstStarted.countDown();
                await(release);
            } else secondFinished.countDown();
        });
        try (var caller = Executors.newSingleThreadExecutor()) {
            var processing = caller.submit(() -> parallel.process(new DpiEngineConfig(input, output, RuleSet.empty(), 8, 2)));
            try {
                assertTrue(firstStarted.await(5, TimeUnit.SECONDS));
                assertTrue(secondFinished.await(5, TimeUnit.SECONDS));
                assertEquals(2, started.get()); // No third packet can enter the full global window.
                assertFalse(processing.isDone());
            } finally { release.countDown(); }
            assertEquals(30, processing.get(5, TimeUnit.SECONDS).stats().writtenPackets());
        }
        assertArrayEquals(Files.readAllBytes(input), Files.readAllBytes(output));
        noWorkersRemain();
    }

    @Test
    void workerFailurePropagatesAndAllWorkersStop() throws Exception {
        Path input = capture(100, 20);
        var parallel = new ParallelDpiEngine(packet -> { throw new IllegalStateException("injected worker failure"); });
        var error = assertThrows(DpiProcessingException.class,
                () -> parallel.process(new DpiEngineConfig(input, temp.resolve("failed.pcap"), RuleSet.empty(), 4, 2)));
        assertTrue(error.getMessage().contains("worker failed"));
        assertInstanceOf(IllegalStateException.class, error.getCause().getCause());
        noWorkersRemain();
    }

    @Test
    void failureOnLaterWorkerInterruptsEarlierBlockedWorkerWithoutDeadlock() throws Exception {
        Path input = capture(20, 20);
        CountDownLatch earlierStarted = new CountDownLatch(1), neverReleased = new CountDownLatch(1);
        var parallel = new ParallelDpiEngine(packet -> {
            if (ByteBuffer.wrap(packet.rawBytes()).getInt() == 0) {
                earlierStarted.countDown(); await(neverReleased);
            } else {
                await(earlierStarted); throw new IllegalStateException("later worker failed");
            }
        });
        assertThrows(DpiProcessingException.class,
                () -> parallel.process(new DpiEngineConfig(input, null, RuleSet.empty(), 8, 2)));
        noWorkersRemain();
    }

    @Test
    void interruptedCallerCancelsAndJoinsWorkers() throws Exception {
        Path input = capture(20, 20);
        CountDownLatch started = new CountDownLatch(1), blocked = new CountDownLatch(1), finished = new CountDownLatch(1);
        AtomicReference<Throwable> failure = new AtomicReference<>();
        AtomicReference<Boolean> interruptRestored = new AtomicReference<>(false);
        var parallel = new ParallelDpiEngine(packet -> { started.countDown(); await(blocked); });
        Thread caller = new Thread(() -> {
            try { parallel.process(new DpiEngineConfig(input, null, RuleSet.empty(), 4, 2)); }
            catch (Throwable error) { failure.set(error); }
            finally { interruptRestored.set(Thread.currentThread().isInterrupted()); finished.countDown(); }
        });
        caller.start();
        try {
            assertTrue(started.await(5, TimeUnit.SECONDS)); caller.interrupt();
            assertTrue(finished.await(5, TimeUnit.SECONDS));
            assertInstanceOf(DpiProcessingException.class, failure.get());
            assertTrue(interruptRestored.get());
        } finally { blocked.countDown(); caller.interrupt(); caller.join(5000); }
        noWorkersRemain();
    }

    @Test
    void truncatedInputDrainsCompleteRecordsThenReportsFailure() throws Exception {
        Path input = capture(10, 3);
        byte[] bytes = Files.readAllBytes(input);
        Files.write(input, java.util.Arrays.copyOf(bytes, 24 + 70 * 3 + 10));
        var error = assertThrows(DpiProcessingException.class,
                () -> engine.process(new DpiEngineConfig(input, null, RuleSet.empty(), 4, 2)));
        assertEquals(3, error.partialStats().totalPacketsRead());
        assertEquals(3, error.partialStats().allowedPackets());
        noWorkersRemain();
    }

    @Test
    void unsupportedPacketsAreNotLost() throws Exception {
        Path input = temp.resolve("unsupported.pcap");
        try (PcapWriter writer = new PcapWriter(input, HEADER)) {
            writer.writePacket(new CapturedPacket(Instant.EPOCH, 1, 1, new byte[]{1}));
            writer.writePacket(new CapturedPacket(Instant.EPOCH, 0, 0, new byte[0]));
        }
        Path output = temp.resolve("unsupported-output.pcap");
        var result = engine.process(new DpiEngineConfig(input, output, demo(), 4, 1));
        assertEquals(2, result.stats().skippedPackets());
        assertEquals(2, result.stats().allowedPackets());
        assertArrayEquals(Files.readAllBytes(input), Files.readAllBytes(output));
    }

    @ParameterizedTest
    @ValueSource(ints = {-1, 0, 65, Integer.MAX_VALUE})
    void rejectsInvalidThreadCounts(int workers) {
        assertThrows(IllegalArgumentException.class, () -> new DpiEngineConfig(Path.of("input.pcap"), null, RuleSet.empty(), workers));
    }

    @ParameterizedTest
    @ValueSource(ints = {0, -1, 4097})
    void rejectsInvalidQueueCapacities(int capacity) {
        assertThrows(IllegalArgumentException.class, () -> new DpiEngineConfig(Path.of("input.pcap"), null, RuleSet.empty(), 4, capacity));
    }

    @Test
    void stableFullTupleHashDistributesAcrossEightWorkers() {
        HashSet<Integer> workers = new HashSet<>();
        for (int port = 10000; port < 10128; port++) {
            FlowKey key = new FlowKey("192.168.1.2", "8.8.8.8", port, 443, 6);
            int worker = ParallelDpiEngine.workerIndex(key, 8);
            assertEquals(worker, ParallelDpiEngine.workerIndex(new FlowKey("192.168.1.2", "8.8.8.8", port, 443, 6), 8));
            workers.add(worker);
        }
        assertEquals(8, workers.size());
    }

    private static void await(CountDownLatch latch) {
        try { latch.await(); }
        catch (InterruptedException e) { Thread.currentThread().interrupt(); throw new IllegalStateException("interrupted", e); }
    }

    @Test
    void timeoutForcesShutdownAndWaitsAgain() throws Exception {
        var executor = new AbstractExecutorService() {
            boolean forced;
            int waits;
            public void shutdown() { }
            public List<Runnable> shutdownNow() { forced = true; return List.of(); }
            public boolean isShutdown() { return true; }
            public boolean isTerminated() { return forced && waits >= 2; }
            public boolean awaitTermination(long timeout, TimeUnit unit) { waits++; return isTerminated(); }
            public void execute(Runnable task) { throw new UnsupportedOperationException(); }
        };
        ParallelDpiEngine.stopExecutors(List.of(executor), false, 100);
        assertTrue(executor.forced);
        assertEquals(2, executor.waits);
    }

    @Test
    void processingFailureRemainsPrimaryWhenWorkerCannotStopWithinDeadline() throws Exception {
        Path input = capture(30, 30);
        CountDownLatch stuck = new CountDownLatch(1), release = new CountDownLatch(1);
        var parallel = new ParallelDpiEngine(packet -> {
            if (ByteBuffer.wrap(packet.rawBytes()).getInt() == 0) {
                stuck.countDown();
                boolean done = false;
                while (!done) {
                    try { release.await(); done = true; }
                    catch (InterruptedException ignored) { /* Simulate code that ignores cancellation. */ }
                }
            } else {
                await(stuck);
                throw new IllegalStateException("primary failure");
            }
        }, 25);
        try {
            var error = assertThrows(DpiProcessingException.class, () -> parallel.process(
                    new DpiEngineConfig(input, null, RuleSet.empty(), 8, 2)));
            assertTrue(error.getMessage().contains("worker failed"));
            assertEquals("primary failure", error.getCause().getCause().getMessage());
            assertEquals(1, error.getCause().getSuppressed().length);
            assertTrue(error.getCause().getSuppressed()[0].getMessage().contains("follow-up wait"));
        } finally {
            release.countDown();
            for (Thread thread : Thread.getAllStackTraces().keySet()) {
                if (thread.getName().startsWith("dpi-worker-")) thread.join(1000);
            }
        }
        noWorkersRemain();
    }
    private static void noWorkersRemain() {
        assertTrue(Thread.getAllStackTraces().keySet().stream().noneMatch(t -> t.isAlive() && t.getName().startsWith("dpi-worker-")));
    }
}
