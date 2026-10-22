package com.dpiengine.engine;

import com.dpiengine.rules.RuleSet;
import java.nio.file.Path;
import java.util.Objects;

/** CLI-independent configuration. Null outputPath selects analysis-only mode. */
public record DpiEngineConfig(Path inputPath, Path outputPath, RuleSet rules, int threads, int queueCapacity,
                              ProcessingLimits limits) {
    public static final int MAX_THREADS = 64;
    public DpiEngineConfig {
        Objects.requireNonNull(inputPath, "inputPath");
        Objects.requireNonNull(rules, "rules");
        Objects.requireNonNull(limits, "limits");
        if (threads < 1 || threads > MAX_THREADS) throw new IllegalArgumentException("Threads must be between 1 and " + MAX_THREADS);
        if (queueCapacity < 1 || queueCapacity > 4096) throw new IllegalArgumentException("Queue capacity must be between 1 and 4096");
    }

    public DpiEngineConfig(Path inputPath, Path outputPath, RuleSet rules, int threads, int queueCapacity) {
        this(inputPath, outputPath, rules, threads, queueCapacity, ProcessingLimits.unrestricted());
    }

    public DpiEngineConfig(Path inputPath, Path outputPath, RuleSet rules) {
        this(inputPath, outputPath, rules, 1, 64);
    }

    public DpiEngineConfig(Path inputPath, Path outputPath, RuleSet rules, int threads) {
        this(inputPath, outputPath, rules, threads, 64);
    }

    public DpiEngineConfig(Path inputPath) {
        this(inputPath, null, RuleSet.empty());
    }
}
