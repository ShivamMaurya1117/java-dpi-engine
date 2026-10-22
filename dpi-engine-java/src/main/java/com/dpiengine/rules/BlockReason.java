package com.dpiengine.rules;

import java.util.Objects;

/** Identifies the configured rule that matched, also retained for subsequent flow packets. */
public record BlockReason(Type type, String value) {
    public enum Type { APPLICATION, DOMAIN, IPV4 }
    public BlockReason {
        Objects.requireNonNull(type);
        Objects.requireNonNull(value);
    }
}
