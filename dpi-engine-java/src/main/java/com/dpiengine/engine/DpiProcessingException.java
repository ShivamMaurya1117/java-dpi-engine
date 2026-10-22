package com.dpiengine.engine;

import com.dpiengine.report.ProcessingStats;
import java.io.IOException;
import java.nio.file.Path;

/** Failure with counts of complete records processed before the error.
 * Output may be incomplete; written counts represent submitted records if flushing failed.
 */
public final class DpiProcessingException extends IOException {
    private final ProcessingStats partialStats;
    private final Path outputPath;

    DpiProcessingException(IOException cause, ProcessingStats partialStats, Path outputPath) {
        super(cause.getMessage(), cause);
        this.partialStats = partialStats;
        this.outputPath = outputPath;
    }

    public ProcessingStats partialStats() { return partialStats; }
    public Path outputPath() { return outputPath; }
}
