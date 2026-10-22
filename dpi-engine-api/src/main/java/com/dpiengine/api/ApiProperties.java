package com.dpiengine.api;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.NotNull;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.util.unit.DataSize;
import org.springframework.validation.annotation.Validated;
import java.nio.file.Path;

@Validated
@ConfigurationProperties("dpi.api")
public record ApiProperties(@NotNull DataSize maxUploadSize, @NotNull Path tempDirectory,
                            @Min(1) @Max(16) int maxConcurrentRequests,
                            @Min(1) @Max(64) int maxWorkersPerRequest,
                            @Min(1) @Max(256) int maxTotalWorkers,
                            @Min(1) long maxPackets, @Min(1) int maxFlows,
                            @Min(1) @Max(67108864) int maxPacketBytes) {
    public ApiProperties {
        if (maxUploadSize != null && maxUploadSize.toBytes() <= 0) {
            throw new IllegalArgumentException("Upload limit must be positive");
        }
    }
}
