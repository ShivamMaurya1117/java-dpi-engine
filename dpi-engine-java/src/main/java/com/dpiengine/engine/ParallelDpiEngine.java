package com.dpiengine.engine;

import com.dpiengine.flow.FlowKey;
import com.dpiengine.flow.FlowState;
import com.dpiengine.flow.FlowTracker;
import com.dpiengine.inspect.AppClassifier;
import com.dpiengine.inspect.AppType;
import com.dpiengine.packet.PacketParser;
import com.dpiengine.packet.ParsedPacket;
import com.dpiengine.pcap.CapturedPacket;
import com.dpiengine.pcap.PcapGlobalHeader;
import com.dpiengine.pcap.PcapReader;
import com.dpiengine.pcap.PcapWriter;
import com.dpiengine.report.ProcessingStats;
import com.dpiengine.rules.BlockReason;
import com.dpiengine.rules.RuleDecision;
import com.dpiengine.rules.RuleEvaluation;
import com.dpiengine.rules.RuleManager;
import com.dpiengine.rules.RuleSet;
import java.io.IOException;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;

/** Flow-affine workers with a globally bounded submission window and serialized ordered output. */
public final class ParallelDpiEngine {
    private final Consumer<CapturedPacket> beforeProcessing;
    private final long shutdownTimeoutMillis;
    public ParallelDpiEngine() { this(packet -> { }); }
    // Package-private failure/backpressure seam; not a CLI or public configuration feature.
    ParallelDpiEngine(Consumer<CapturedPacket> beforeProcessing) { this(beforeProcessing, 30_000); }
    ParallelDpiEngine(Consumer<CapturedPacket> beforeProcessing, long shutdownTimeoutMillis) {
        this.beforeProcessing = beforeProcessing;
        this.shutdownTimeoutMillis = shutdownTimeoutMillis;
    }

    static int workerIndex(FlowKey key, int workers) {
        if (workers < 1 || workers > DpiEngineConfig.MAX_THREADS) throw new IllegalArgumentException("Invalid worker count");
        int hash = key.hashCode();
        return Math.floorMod(hash ^ (hash >>> 16), workers);
    }

    public DpiProcessingResult process(DpiEngineConfig config) throws DpiProcessingException {
        long start = System.nanoTime();
        Counts counts = new Counts();
        List<Worker> workers = new ArrayList<>();
        AtomicReference<Throwable> failure = new AtomicReference<>();
        Path outputPath = null;
        PcapGlobalHeader header;
        try (PcapReader reader = new PcapReader(config.inputPath(), config.limits().maxPacketBytes())) {
            header = reader.globalHeader();
            if (config.outputPath() != null) outputPath = PcapWriter.validateOutputPath(config.inputPath(), config.outputPath());
            try (PcapWriter writer = outputPath == null ? null : new PcapWriter(outputPath, header)) {
                boolean finished = false;
                Throwable primaryFailure = null;
                try {
                    for (int i = 0; i < config.threads(); i++) workers.add(new Worker(i, config.rules(), config.queueCapacity()));
                    PacketParser parser = new PacketParser();
                    // Admission happens on the reader thread, so the flow limit is global across workers.
                    var admittedFlows = new HashSet<FlowKey>();
                    ArrayDeque<Pending> pending = new ArrayDeque<>();
                    IOException inputError = null;
                    while (true) {
                        // Limits all queued, processing and completed-but-unwritten packets together.
                        if (pending.size() >= config.queueCapacity()) consume(pending.removeFirst(), writer, counts, failure);
                        checkFailure(failure);
                        Optional<CapturedPacket> next;
                        try { next = reader.readPacket(); }
                        catch (IOException e) { inputError = e; break; }
                        if (next.isEmpty()) break;
                        if (counts.total >= config.limits().maxPackets()) throw new ProcessingLimitException(
                                "PCAP exceeds record budget of " + config.limits().maxPackets() + "; split the capture");
                        CapturedPacket captured = next.orElseThrow();
                        long sequence = counts.total++;
                        Optional<ParsedPacket> parsed = header.network() == 1 ? parser.parse(captured) : Optional.empty();
                        ParsedPacket packet = parsed.orElse(null);
                        if (packet != null) {
                            FlowKey key = FlowKey.from(packet);
                            if (!admittedFlows.contains(key) && admittedFlows.size() >= config.limits().maxFlows()) {
                                throw new ProcessingLimitException("PCAP exceeds flow budget of "
                                        + config.limits().maxFlows() + "; split the capture");
                            }
                            admittedFlows.add(key);
                        }
                        int worker = packet == null ? (int) (sequence % workers.size())
                                : workerIndex(FlowKey.from(packet), workers.size());
                        if (packet != null) {
                            counts.parsed++;
                            if (packet.isTcp()) counts.tcp++;
                            if (packet.isUdp()) counts.udp++;
                        }
                        Worker target = workers.get(worker);
                        Future<Outcome> future = target.executor.submit(() -> {
                            try {
                                beforeProcessing.accept(captured);
                                RuleEvaluation decision = RuleEvaluation.allow();
                                if (packet != null) {
                                    var inspection = target.classifier.inspect(captured, packet);
                                    var flow = target.tracker.track(captured, packet, inspection);
                                    decision = target.rules.evaluate(packet, inspection, flow);
                                }
                                return new Outcome(sequence, captured, decision);
                            } catch (Throwable e) {
                                failure.compareAndSet(null, e);
                                throw e;
                            }
                        });
                        pending.addLast(new Pending(sequence, future));
                    }
                    while (!pending.isEmpty()) consume(pending.removeFirst(), writer, counts, failure);
                    finished = true;
                    if (inputError != null) throw inputError;
                } catch (IOException | RuntimeException | Error e) {
                    primaryFailure = e;
                    throw e;
                } finally {
                    try {
                        stopExecutors(workers.stream().map(worker -> worker.executor).toList(),
                                !finished, shutdownTimeoutMillis);
                    } catch (IOException shutdownFailure) {
                        if (primaryFailure != null) primaryFailure.addSuppressed(shutdownFailure);
                        else throw shutdownFailure;
                    }
                }
            }
        } catch (IOException | RuntimeException e) {
            IOException cause = e instanceof IOException io ? io : new IOException("Parallel processing failed", e);
            throw new DpiProcessingException(cause, counts.snapshot(workers, start), outputPath);
        }
        Map<FlowKey, FlowState> flows = new HashMap<>();
        for (Worker worker : workers) flows.putAll(worker.tracker.flows());
        return new DpiProcessingResult(config.inputPath().toAbsolutePath().normalize(), outputPath, header,
                counts.snapshot(workers, start), flows);
    }

    private record Outcome(long sequence, CapturedPacket packet, RuleEvaluation evaluation) { }
    private record Pending(long sequence, Future<Outcome> future) { }

    private static void consume(Pending pending, PcapWriter writer, Counts counts,
                                AtomicReference<Throwable> failure) throws IOException {
        Outcome outcome;
        try {
            while (true) {
                checkFailure(failure);
                try { outcome = pending.future().get(100, TimeUnit.MILLISECONDS); break; }
                catch (TimeoutException e) { /* Check other workers' failures while awaiting this sequence. */ }
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Parallel processing interrupted", e);
        } catch (ExecutionException e) {
            throw new IOException("DPI worker failed", e.getCause());
        }
        if (outcome.sequence() != pending.sequence()) throw new IOException("Packet sequence mismatch");
        if (outcome.evaluation().decision() == RuleDecision.BLOCK) {
            counts.blocked++;
            for (BlockReason reason : outcome.evaluation().reasons()) counts.reasons.merge(reason, 1L, Long::sum);
        } else {
            counts.allowed++;
            if (writer != null) { writer.writePacket(outcome.packet()); counts.written++; }
        }
    }

    private static void checkFailure(AtomicReference<Throwable> failure) throws IOException {
        if (failure.get() != null) throw new IOException("DPI worker failed", failure.get());
    }

    static void stopExecutors(List<? extends ExecutorService> executors, boolean cancel, long timeoutMillis) throws IOException {
        boolean interrupted = Thread.interrupted();
        try {
            for (ExecutorService executor : executors) {
                if (cancel || interrupted) executor.shutdownNow();
                else executor.shutdown();
            }
            // One shared deadline per phase, rather than a full timeout for every worker.
            for (int phase = 0; phase < 2; phase++) {
                long deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(timeoutMillis);
                for (ExecutorService executor : executors) {
                    while (!executor.isTerminated()) {
                        long remaining = deadline - System.nanoTime();
                        if (remaining <= 0) break;
                        try {
                            if (!executor.awaitTermination(remaining, TimeUnit.NANOSECONDS)) break;
                        } catch (InterruptedException e) {
                            interrupted = true;
                            for (ExecutorService other : executors) other.shutdownNow();
                        }
                    }
                }
                if (executors.stream().allMatch(ExecutorService::isTerminated)) return;
                for (ExecutorService executor : executors) executor.shutdownNow();
            }
            throw new IOException("DPI worker did not terminate after forced shutdown and follow-up wait");
        } finally {
            if (interrupted) Thread.currentThread().interrupt();
        }
    }

    private static final class Worker {
        final FlowTracker tracker = new FlowTracker();
        final RuleManager rules;
        final AppClassifier classifier = new AppClassifier();
        final ThreadPoolExecutor executor;
        Worker(int index, RuleSet rules, int capacity) {
            this.rules = new RuleManager(rules);
            executor = new ThreadPoolExecutor(1, 1, 0, TimeUnit.MILLISECONDS,
                    new ArrayBlockingQueue<>(capacity), task -> new Thread(task, "dpi-worker-" + index));
        }
    }

    private static final class Counts {
        long total, parsed, tcp, udp, allowed, blocked, written;
        final Map<BlockReason, Long> reasons = new HashMap<>();
        ProcessingStats snapshot(List<Worker> workers, long start) {
            int flows = 0, blockedFlows = 0;
            Map<AppType, Long> apps = new EnumMap<>(AppType.class);
            for (Worker worker : workers) {
                if (!worker.executor.isTerminated()) continue; // Never inspect mutable state of a stuck worker.
                flows += worker.tracker.uniqueFlowCount();
                blockedFlows += worker.rules.blockedFlows().size();
                worker.tracker.applicationDistribution().forEach((app, count) -> apps.merge(app, count, Long::sum));
            }
            return new ProcessingStats(total, parsed, total - parsed, tcp, udp, flows, apps, allowed, blocked,
                    written, blockedFlows, reasons, Duration.ofNanos(System.nanoTime() - start));
        }
    }
}
