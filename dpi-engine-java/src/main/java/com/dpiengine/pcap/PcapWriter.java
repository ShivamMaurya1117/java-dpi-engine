package com.dpiengine.pcap;

import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;

/** Sequential classic-PCAP writer. Owns its output; existing files are never overwritten. */
public final class PcapWriter implements AutoCloseable {
    private final OutputStream output;
    private final PcapGlobalHeader header;
    private boolean closed;
    private boolean failed;
    private long writtenPackets;

    public PcapWriter(Path path, PcapGlobalHeader header) throws IOException {
        this(open(path, header), header);
    }

    /** Stream constructor supports reusable outputs and explicit I/O failure testing. */
    public PcapWriter(OutputStream output, PcapGlobalHeader header) throws IOException {
        this.header = header;
        this.output = new BufferedOutputStream(output);
        try {
            validateHeader(header);
            ByteBuffer bytes = ByteBuffer.allocate(24).order(header.byteOrder());
            bytes.putInt(header.nanosecondResolution() ? 0xa1b23c4d : 0xa1b2c3d4)
                    .putShort((short) header.versionMajor()).putShort((short) header.versionMinor())
                    .putInt(header.thisZone()).putInt((int) header.sigFigs())
                    .putInt((int) header.snapLength()).putInt((int) header.network());
            this.output.write(bytes.array());
        } catch (IOException | RuntimeException e) {
            try { this.output.close(); } catch (IOException closeError) { e.addSuppressed(closeError); }
            throw e;
        }
    }

    private static OutputStream open(Path path, PcapGlobalHeader header) throws IOException {
        validateHeader(header);
        return Files.newOutputStream(path, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
    }

    private static void validateHeader(PcapGlobalHeader header) throws IOException {
        if (header == null || header.byteOrder() == null || header.versionMajor() != 2 || header.versionMinor() != 4
                || !unsigned(header.sigFigs()) || !unsigned(header.snapLength()) || header.snapLength() == 0
                || !unsigned(header.network())) throw new IOException("Invalid classic PCAP global header");
    }

    public void writePacket(CapturedPacket packet) throws IOException {
        if (closed) throw new IOException("PCAP writer is closed");
        if (failed) throw new IOException("PCAP writer cannot continue after an I/O failure");
        if (packet == null || packet.timestamp() == null) throw new IOException("Missing packet timestamp");
        byte[] raw = packet.rawBytes();
        long captured = packet.capturedLength(), original = packet.originalLength();
        long seconds = packet.timestamp().getEpochSecond();
        int nanos = packet.timestamp().getNano();
        if (!unsigned(captured) || !unsigned(original) || captured != raw.length
                || captured > original || captured > header.snapLength() || !unsigned(seconds)) {
            throw new IOException("Invalid PCAP packet lengths or timestamp");
        }
        if (!header.nanosecondResolution() && nanos % 1000 != 0) {
            throw new IOException("Packet timestamp cannot be preserved at microsecond precision");
        }
        ByteBuffer metadata = ByteBuffer.allocate(16).order(header.byteOrder());
        metadata.putInt((int) seconds).putInt(header.nanosecondResolution() ? nanos : nanos / 1000)
                .putInt((int) captured).putInt((int) original);
        try {
            output.write(metadata.array());
            output.write(raw);
            writtenPackets++;
        } catch (IOException e) {
            failed = true;
            throw e;
        }
    }

    /** Buffered writes are guaranteed complete only after successful close. */
    public long writtenPackets() { return writtenPackets; }

    private static boolean unsigned(long value) { return value >= 0 && value <= 0xffffffffL; }

    /** Rejects identical paths, aliases, and existing output files before writing. */
    public static Path validateOutputPath(Path input, Path output) throws IOException {
        Path source = input.toRealPath();
        if (!Files.isRegularFile(source)) throw new IOException("Input must be a regular PCAP file");
        Path target = output.toAbsolutePath().normalize();
        if (source.equals(target) || (Files.exists(target) && Files.isSameFile(source, target))) {
            throw new IOException("Output must not overwrite the input PCAP");
        }
        if (Files.exists(target)) throw new IOException("Output already exists: " + target);
        if (target.getParent() == null || !Files.isDirectory(target.getParent())) {
            throw new IOException("Output parent directory does not exist: " + target);
        }
        return target;
    }

    @Override
    public void close() throws IOException {
        if (closed) return;
        closed = true;
        output.close();
    }
}
