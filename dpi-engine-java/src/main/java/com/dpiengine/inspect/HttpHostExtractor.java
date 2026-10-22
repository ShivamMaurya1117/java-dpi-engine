package com.dpiengine.inspect;

import java.nio.charset.StandardCharsets;
import java.util.Optional;

/** Reads complete HTTP/1 request headers only; never searches the request body. */
public final class HttpHostExtractor {
    private static final int MAX_HEADER_BYTES = 65536;

    public Optional<String> extract(byte[] data, int offset, int length) {
        if (data == null || offset < 0 || length < 0 || offset > data.length || length > data.length - offset) {
            return Optional.empty();
        }
        int end = offset + Math.min(length, MAX_HEADER_BYTES);
        int headerEnd = -1;
        for (int i = offset; i + 3 < end; i++) {
            if (data[i] == '\r' && data[i + 1] == '\n' && data[i + 2] == '\r' && data[i + 3] == '\n') {
                headerEnd = i;
                break;
            }
        }
        if (headerEnd < 0) return Optional.empty();
        for (int i = offset; i < headerEnd; i++) {
            int value = Byte.toUnsignedInt(data[i]);
            if (value > 126 || (value < 32 && value != 9 && value != 13 && value != 10)) return Optional.empty();
        }
        String[] lines = new String(data, offset, headerEnd - offset, StandardCharsets.US_ASCII).split("\r\n", -1);
        if (!lines[0].matches("(?:GET|POST|PUT|HEAD|DELETE|PATCH|OPTIONS) [^\\s]+ HTTP/1\\.[01]")) return Optional.empty();
        Optional<String> host = Optional.empty();
        boolean sawHost = false;
        for (int i = 1; i < lines.length; i++) {
            int colon = lines[i].indexOf(':');
            if (colon < 1 || !lines[i].substring(0, colon).matches("[!#$%&'*+.^_`|~A-Za-z0-9-]+")) return Optional.empty();
            if (!lines[i].substring(0, colon).equalsIgnoreCase("Host")) continue;
            if (sawHost) return Optional.empty();
            sawHost = true;
            String value = lines[i].substring(colon + 1).trim();
            int portStart = value.indexOf(':');
            if (portStart >= 0) {
                String port = value.substring(portStart + 1);
                if (!port.matches("[0-9]{1,5}")) return Optional.empty();
                int number = Integer.parseInt(port);
                if (number == 0 || number > 65535) return Optional.empty();
                value = value.substring(0, portStart);
            }
            host = Hostnames.normalize(value);
            if (host.isEmpty()) return Optional.empty();
        }
        return host;
    }
}
