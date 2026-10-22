package com.dpiengine.api;

import com.dpiengine.inspect.AppType;
import com.dpiengine.rules.RuleSet;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.Size;
import jakarta.validation.constraints.NotBlank;
import io.swagger.v3.oas.annotations.media.Schema;
import java.util.List;
import java.util.Locale;

public record DpiOptions(@Min(1) @Max(64) @Schema(defaultValue="1") Integer workers,
                         @Size(max=256) List<@NotBlank String> blockedApplications,
                         @Size(max=256) List<@NotBlank String> blockedDomains,
                         @Size(max=256) List<@NotBlank String> blockedIpv4Addresses) {
    public static DpiOptions defaults() { return new DpiOptions(1, List.of(), List.of(), List.of()); }
    public int workerCount() { return workers == null ? 1 : workers; }
    public RuleSet rules() {
        RuleSet.Builder builder = RuleSet.builder();
        if (blockedApplications != null) for (String app : blockedApplications) {
            if (app == null) throw new IllegalArgumentException("Application must not be null");
            builder.blockApplication(AppType.valueOf(app.toUpperCase(Locale.ROOT)));
        }
        if (blockedDomains != null) for (String domain : blockedDomains) {
            if (domain == null) throw new IllegalArgumentException("Domain must not be null");
            builder.blockDomain(domain);
        }
        if (blockedIpv4Addresses != null) for (String ip : blockedIpv4Addresses) {
            if (ip == null) throw new IllegalArgumentException("IPv4 address must not be null");
            builder.blockIpv4(ip);
        }
        return builder.build();
    }
}
