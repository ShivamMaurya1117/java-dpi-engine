package com.dpiengine.inspect;

import java.util.Optional;
import com.dpiengine.inspect.PayloadCursor.MalformedPayload;

/** Extracts the first query name after validating every question.
 * Compression pointers in questions are safely skipped as unsupported.
 * TCP callers must strip the two-byte DNS message-length prefix.
 */
public final class DnsQueryExtractor {
    public Optional<String> extract(byte[] data, int offset, int length) {
        try {
            PayloadCursor dns = new PayloadCursor(data, offset, length);
            dns.skip(2);
            int flags = dns.u16();
            if ((flags & 0xf800) != 0) return Optional.empty(); // Query, standard opcode.
            int questions = dns.u16();
            dns.skip(6);
            if (questions == 0 || questions > dns.remaining() / 5) return Optional.empty();
            Optional<String> first = Optional.empty();
            for (int question = 0; question < questions; question++) {
                StringBuilder name = new StringBuilder();
                while (true) {
                    int labelLength = dns.u8();
                    if (labelLength == 0) break;
                    if (labelLength > 63) return Optional.empty();
                    if (!name.isEmpty()) name.append('.');
                    name.append(dns.ascii(labelLength));
                    if (name.length() > 253) return Optional.empty();
                }
                Optional<String> hostname = Hostnames.normalize(name.toString());
                if (hostname.isEmpty() || dns.u16() == 0 || dns.u16() == 0) return Optional.empty();
                if (question == 0) first = hostname;
            }
            return first;
        } catch (MalformedPayload e) {
            return Optional.empty();
        }
    }
}
