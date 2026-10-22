package com.dpiengine.pcap;

import java.io.BufferedInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Optional;

/** Sequential classic-PCAP reader. Owns its stream and must be closed by the caller. */
public final class PcapReader implements AutoCloseable {
    /** Allocation ceiling per packet; oversized records are rejected before allocation. */
    public static final int MAX_CAPTURED_LENGTH = 64 * 1024 * 1024;

    private final InputStream input;
    private final PcapGlobalHeader globalHeader;
    private final int maxCapturedLength;
    private boolean eof;
    private boolean closed;
    private boolean failed;

    public PcapReader(Path path) throws IOException {
        this(path, MAX_CAPTURED_LENGTH);
    }

    public PcapReader(Path path, int maxCapturedLength) throws IOException {
        if (maxCapturedLength < 1 || maxCapturedLength > MAX_CAPTURED_LENGTH) {
            throw new IllegalArgumentException("Invalid PCAP record allocation limit");
        }
        this.maxCapturedLength = maxCapturedLength;
        input = new BufferedInputStream(Files.newInputStream(path));
        try {
            globalHeader = readGlobalHeader();
        } catch (IOException | RuntimeException e) {
            try {
                input.close();
            } catch (IOException closeError) {
                e.addSuppressed(closeError);
            }
            throw e;
        }
    }

    public PcapGlobalHeader globalHeader() {
        return globalHeader;
    }

    /** Returns empty only at a clean record boundary; partial records throw EOFException. */
    public Optional<CapturedPacket> readPacket() throws IOException {
        if (closed) throw new IOException("PCAP reader is closed");
        if (failed) throw new IOException("PCAP reader cannot continue after a read failure");
        if (eof) return Optional.empty();
        try {
            byte[] header = input.readNBytes(16);
            if (header.length == 0) {
                eof = true;
                return Optional.empty();
            }
            if (header.length != 16) throw new EOFException("Truncated PCAP packet header");
            ByteBuffer buffer = ByteBuffer.wrap(header).order(globalHeader.byteOrder());
            long seconds = unsigned(buffer.getInt());
            long fraction = unsigned(buffer.getInt());
            long captured = unsigned(buffer.getInt());
            long original = unsigned(buffer.getInt());
            long units = globalHeader.nanosecondResolution() ? 1_000_000_000L : 1_000_000L;
            if (fraction >= units) throw new PcapFormatException("Invalid PCAP timestamp fraction: " + fraction);
            if (captured > original || captured > globalHeader.snapLength()) {
                throw new PcapFormatException("Invalid PCAP captured length: " + captured);
            }
            if (captured > MAX_CAPTURED_LENGTH) {
                throw new PcapFormatException("PCAP packet exceeds allocation limit: " + captured);
            }
            if (captured > maxCapturedLength) throw new PcapLimitException(
                    "PCAP record exceeds captured-byte budget of " + maxCapturedLength + "; use a smaller capture snapshot length");
            byte[] bytes = readExact((int) captured, "packet data");
            Instant timestamp = Instant.ofEpochSecond(seconds,
                    globalHeader.nanosecondResolution() ? fraction : fraction * 1_000L);
            return Optional.of(new CapturedPacket(timestamp, captured, original, bytes));
        } catch (IOException e) {
            failed = true;
            throw e;
        }
    }

    private PcapGlobalHeader readGlobalHeader() throws IOException {
        byte[] bytes = readExact(24, "global header");
        int magic = ByteBuffer.wrap(bytes).getInt();
        ByteOrder order;
        boolean nanos;
        switch (magic) {
            case 0xa1b2c3d4 -> { order = ByteOrder.BIG_ENDIAN; nanos = false; }
            case 0xd4c3b2a1 -> { order = ByteOrder.LITTLE_ENDIAN; nanos = false; }
            case 0xa1b23c4d -> { order = ByteOrder.BIG_ENDIAN; nanos = true; }
            case 0x4d3cb2a1 -> { order = ByteOrder.LITTLE_ENDIAN; nanos = true; }
            default -> throw new PcapFormatException("Unsupported PCAP magic number");
        }
        ByteBuffer buffer = ByteBuffer.wrap(bytes).order(order);
        buffer.position(4);
        int major = Short.toUnsignedInt(buffer.getShort());
        int minor = Short.toUnsignedInt(buffer.getShort());
        int zone = buffer.getInt();
        long sigFigs = unsigned(buffer.getInt());
        long snapLength = unsigned(buffer.getInt());
        long network = unsigned(buffer.getInt());
        if (major != 2 || minor != 4) throw new PcapFormatException("Unsupported PCAP version: " + major + "." + minor);
        if (snapLength == 0) throw new PcapFormatException("Invalid PCAP snapshot length: 0");
        return new PcapGlobalHeader(order, nanos, major, minor, zone, sigFigs, snapLength, network);
    }

    private byte[] readExact(int length, String field) throws IOException {
        byte[] bytes = input.readNBytes(length);
        if (bytes.length != length) throw new EOFException("Truncated PCAP " + field);
        return bytes;
    }

    private static long unsigned(int value) {
        return Integer.toUnsignedLong(value);
    }

    @Override
    public void close() throws IOException {
        closed = true;
        input.close();
    }
}
