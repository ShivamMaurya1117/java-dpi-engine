package com.dpiengine;

import com.dpiengine.engine.DpiEngine;
import com.dpiengine.engine.DpiEngineConfig;
import com.dpiengine.engine.DpiProcessingException;
import com.dpiengine.engine.DpiProcessingResult;
import com.dpiengine.flow.FlowState;
import com.dpiengine.inspect.AppType;
import com.dpiengine.report.ProcessingStats;
import com.dpiengine.rules.RuleSet;
import java.nio.file.Path;
import java.util.Locale;
import java.util.Map;

public class Main {
    public static void main(String[] args) {
        Configuration configuration;
        try {
            configuration = configure(args);
        } catch (IllegalArgumentException e) {
            System.err.println("Invalid configuration: " + e.getMessage());
            System.err.println("Usage: Main [pcap] [--threads 1..64] [--output PATH] [--demo-rules] [--block-app APP] [--block-domain DOMAIN] [--block-ip IPV4]");
            System.exit(1);
            return;
        }
        try {
            DpiEngineConfig config = new DpiEngineConfig(configuration.path(), configuration.output(), configuration.rules(), configuration.threads());
            display(new DpiEngine().process(config), configuration.enabled());
        } catch (DpiProcessingException e) {
            System.err.println("PCAP processing failed for " + configuration.path() + ": " + e.getMessage());
            System.err.println("Complete packets read before failure: " + e.partialStats().totalPacketsRead());
            if (e.outputPath() != null) System.err.println("Output may be incomplete: " + e.outputPath());
            System.exit(1);
        }
    }

    private static void display(DpiProcessingResult result, boolean rulesEnabled) {
        ProcessingStats stats = result.stats();
        System.out.println("Total packets read: " + stats.totalPacketsRead());
        System.out.println("Successfully parsed packets: " + stats.successfullyParsedPackets());
        System.out.println("TCP packet count: " + stats.tcpPackets());
        System.out.println("UDP packet count: " + stats.udpPackets());
        System.out.println("Skipped/unsupported packet count: " + stats.skippedPackets());
        System.out.println("Total unique flows: " + stats.uniqueFlows());
        System.out.println("Rules enabled: " + rulesEnabled);
        System.out.println("Allowed packet count: " + stats.allowedPackets());
        System.out.println("Blocked packet count: " + stats.blockedPackets());
        System.out.println("Written packet count: " + stats.writtenPackets());
        System.out.println("Output file path: " + (result.outputPath() == null ? "none (analysis only)" : result.outputPath()));
        System.out.println("Processing duration (ms): " + stats.processingDuration().toNanos() / 1_000_000.0);
        if (rulesEnabled) {
            System.out.println("Blocked flow count: " + stats.blockedFlows());
            System.out.println("Block reasons (packet counts; multiple reasons may overlap):");
            stats.blockingReasons().entrySet().stream()
                    .sorted(java.util.Comparator.comparing(entry -> entry.getKey().toString()))
                    .forEach(entry -> System.out.println("  " + entry.getKey().type() + " "
                            + entry.getKey().value() + ": " + entry.getValue()));
        }
        System.out.println("Top 5 flows by packet count:");
        for (FlowState flow : result.topFlows(5)) {
            System.out.println("  " + flow.key() + " packets=" + flow.packetCount()
                    + " capturedBytes=" + flow.totalCapturedBytes() + " status=" + flow.status()
                    + " first=" + flow.firstPacketTimestamp() + " last=" + flow.lastPacketTimestamp());
        }
        System.out.println("Application distribution by flow:");
        Map<AppType, Long> distribution = stats.applicationDistribution();
        for (AppType app : AppType.values()) {
            if (distribution.containsKey(app)) System.out.println("  " + app + ": " + distribution.get(app));
        }
        System.out.println("Example extracted hostnames:");
        result.flows().values().stream().filter(flow -> !flow.hostname().isEmpty())
                .map(flow -> flow.hostname() + " (" + flow.appType() + ")")
                .distinct().sorted().limit(20).forEach(name -> System.out.println("  " + name));
    }

    private record Configuration(Path path, Path output, RuleSet rules, boolean enabled, int threads) { }

    private static Configuration configure(String[] args) {
        Path path = Path.of("../test_dpi.pcap");
        Path output = null;
        boolean pathSet = false, enabled = false;
        int threads = 1;
        RuleSet.Builder rules = RuleSet.builder();
        for (int i = 0; i < args.length; i++) {
            String argument = args[i];
            switch (argument) {
                case "--threads" -> {
                    if (++i >= args.length) throw new IllegalArgumentException("Missing value for --threads");
                    threads = Integer.parseInt(args[i]);
                    if (threads < 1 || threads > DpiEngineConfig.MAX_THREADS) throw new IllegalArgumentException("Threads must be between 1 and " + DpiEngineConfig.MAX_THREADS);
                }
                case "--output" -> {
                    if (++i >= args.length || args[i].startsWith("--")) throw new IllegalArgumentException("Missing value for --output");
                    if (output != null) throw new IllegalArgumentException("--output may only be specified once");
                    output = Path.of(args[i]);
                }
                case "--demo-rules" -> {
                    enabled = true;
                    rules.blockApplication(AppType.YOUTUBE).blockDomain("facebook.com").blockIpv4("192.168.1.50");
                }
                case "--block-app", "--block-domain", "--block-ip" -> {
                    if (++i >= args.length) throw new IllegalArgumentException("Missing value for " + argument);
                    enabled = true;
                    switch (argument) {
                        case "--block-app" -> rules.blockApplication(AppType.valueOf(args[i].toUpperCase(Locale.ROOT)));
                        case "--block-domain" -> rules.blockDomain(args[i]);
                        case "--block-ip" -> rules.blockIpv4(args[i]);
                        default -> throw new IllegalArgumentException("Unknown option: " + argument);
                    }
                }
                default -> {
                    if (argument.startsWith("--") || pathSet) throw new IllegalArgumentException("Unexpected argument: " + argument);
                    path = Path.of(argument);
                    pathSet = true;
                }
            }
        }
        return new Configuration(path, output, rules.build(), enabled, threads);
    }
}
