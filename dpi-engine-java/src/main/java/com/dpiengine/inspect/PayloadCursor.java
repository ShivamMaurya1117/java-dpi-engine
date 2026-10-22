package com.dpiengine.inspect;

import java.nio.charset.StandardCharsets;

/** Bounds are narrowed at every protocol length field. Never reads beyond its slice. */
final class PayloadCursor {
    private final byte[] data;
    private int position;
    private final int end;

    PayloadCursor(byte[] data, int offset, int length) {
        if (data == null || offset < 0 || length < 0 || offset > data.length || length > data.length - offset) {
            throw new MalformedPayload();
        }
        this.data = data;
        position = offset;
        end = offset + length;
    }

    int remaining() { return end - position; }
    int u8() { require(1); return Byte.toUnsignedInt(data[position++]); }
    int u16() { return (u8() << 8) | u8(); }
    int u24() { return (u8() << 16) | u16(); }
    void skip(int count) { require(count); position += count; }
    PayloadCursor slice(int count) {
        require(count);
        PayloadCursor result = new PayloadCursor(data, position, count);
        position += count;
        return result;
    }
    String ascii(int count) {
        require(count);
        for (int i = position; i < position + count; i++) {
            if (data[i] < 0 || data[i] < 0x20 || data[i] == 0x7f) throw new MalformedPayload();
        }
        String result = new String(data, position, count, StandardCharsets.US_ASCII);
        position += count;
        return result;
    }
    private void require(int count) {
        if (count < 0 || count > remaining()) throw new MalformedPayload();
    }
    static final class MalformedPayload extends RuntimeException { }
}
