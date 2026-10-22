package com.dpiengine.inspect;

import java.util.Objects;

/** Empty hostname means no complete valid hostname was extracted. */
public record InspectionResult(AppType appType, String hostname) {
    public InspectionResult {
        Objects.requireNonNull(appType);
        Objects.requireNonNull(hostname);
    }
}
