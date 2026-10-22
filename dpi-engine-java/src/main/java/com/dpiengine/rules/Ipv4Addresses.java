package com.dpiengine.rules;

import java.util.Optional;

/** Strict dotted-decimal literals only; never performs DNS lookup. */
final class Ipv4Addresses {
    private Ipv4Addresses() { }
    static Optional<String> normalize(String address) {
        if (address == null || address.length() > 15) return Optional.empty();
        String[] octets = address.split("\\.", -1);
        if (octets.length != 4) return Optional.empty();
        for (String octet : octets) {
            if (!octet.matches("0|[1-9][0-9]{0,2}") || Integer.parseInt(octet) > 255) return Optional.empty();
        }
        return Optional.of(address);
    }
}
