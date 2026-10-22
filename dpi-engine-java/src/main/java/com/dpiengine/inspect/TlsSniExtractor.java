package com.dpiengine.inspect;

import java.util.Optional;
import com.dpiengine.inspect.PayloadCursor.MalformedPayload;

/** Extracts cleartext SNI from a complete ClientHello in a single TLS record.
 * Split records/handshakes, encrypted SNI, and stream reassembly are unsupported.
 */
public final class TlsSniExtractor {
    public Optional<String> extract(byte[] data, int offset, int length) {
        try {
            PayloadCursor payload = new PayloadCursor(data, offset, length);
            if (payload.u8() != 0x16) return Optional.empty();
            int version = payload.u16();
            if (version < 0x0300 || version > 0x0304) return Optional.empty();
            PayloadCursor record = payload.slice(payload.u16());
            if (record.u8() != 1) return Optional.empty();
            PayloadCursor hello = record.slice(record.u24());
            int clientVersion = hello.u16();
            if (clientVersion < 0x0300 || clientVersion > 0x0304) return Optional.empty();
            hello.skip(32);
            int sessionLength = hello.u8();
            if (sessionLength > 32) return Optional.empty();
            hello.skip(sessionLength);
            int cipherLength = hello.u16();
            if (cipherLength < 2 || (cipherLength & 1) != 0) return Optional.empty();
            hello.skip(cipherLength);
            int compressionLength = hello.u8();
            if (compressionLength == 0) return Optional.empty();
            hello.skip(compressionLength);
            if (hello.remaining() == 0) return Optional.empty(); // No extensions.
            PayloadCursor extensions = hello.slice(hello.u16());
            if (hello.remaining() != 0) return Optional.empty();
            Optional<String> hostname = Optional.empty();
            boolean sawSni = false;
            while (extensions.remaining() > 0) {
                int type = extensions.u16();
                PayloadCursor extension = extensions.slice(extensions.u16());
                if (type != 0) continue;
                if (sawSni) return Optional.empty();
                sawSni = true;
                PayloadCursor names = extension.slice(extension.u16());
                if (extension.remaining() != 0 || names.remaining() == 0) return Optional.empty();
                while (names.remaining() > 0) {
                    int nameType = names.u8();
                    int nameLength = names.u16();
                    if (nameLength == 0) return Optional.empty();
                    if (nameType == 0) {
                        if (hostname.isPresent()) return Optional.empty();
                        hostname = Hostnames.normalize(names.ascii(nameLength));
                        if (hostname.isEmpty()) return Optional.empty();
                    } else {
                        names.skip(nameLength);
                    }
                }
            }
            return hostname;
        } catch (MalformedPayload e) {
            return Optional.empty();
        }
    }
}
