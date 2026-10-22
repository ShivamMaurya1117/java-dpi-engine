package com.dpiengine.inspect;

import java.util.Locale;
import java.util.Optional;

/** Shared hostname normalization for inspection and domain rules. */
public final class Hostnames {
    private Hostnames() { }

    public static Optional<String> normalize(String name) {
        if (name == null) return Optional.empty();
        if (name.endsWith(".")) name = name.substring(0, name.length() - 1);
        if (name.isEmpty() || name.length() > 253) return Optional.empty();
        for (String label : name.split("\\.", -1)) {
            if (label.isEmpty() || label.length() > 63 || !label.matches("[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?")) {
                return Optional.empty();
            }
        }
        return Optional.of(name.toLowerCase(Locale.ROOT));
    }
}
