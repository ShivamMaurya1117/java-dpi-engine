package com.dpiengine.pcap;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import static org.junit.jupiter.api.Assertions.*;

class PcapWriterTest {
    @TempDir Path temp;
    private PcapGlobalHeader header(boolean little, boolean nanos) {
        return new PcapGlobalHeader(little ? ByteOrder.LITTLE_ENDIAN : ByteOrder.BIG_ENDIAN,
                nanos, 2, 4, -3600, 0xffffffffL, 65535, 0x80000001L);
    }

    @ParameterizedTest
    @CsvSource({"true,false", "false,false", "true,true", "false,true"})
    void preservesHeaderAndEveryPacketField(boolean little, boolean nanos) throws IOException {
        PcapGlobalHeader header = header(little, nanos);
        Path output = temp.resolve("capture.pcap");
        CapturedPacket packet = new CapturedPacket(Instant.ofEpochSecond(0xffffffffL, nanos ? 123456789 : 123456000),
                3, 0xffffffffL, new byte[]{0, (byte) 0x80, (byte) 0xff});
        try (PcapWriter writer = new PcapWriter(output, header)) {
            writer.writePacket(packet);
            writer.writePacket(new CapturedPacket(Instant.EPOCH, 0, 0, new byte[0]));
            assertEquals(2, writer.writtenPackets());
        }
        byte[] bytes = Files.readAllBytes(output);
        assertEquals(59, bytes.length);
        ByteBuffer binary = ByteBuffer.wrap(bytes).order(header.byteOrder());
        assertEquals(nanos ? 0xa1b23c4d : 0xa1b2c3d4, binary.getInt());
        assertEquals(2, binary.getShort()); assertEquals(4, binary.getShort());
        assertEquals(-3600, binary.getInt()); assertEquals(-1, binary.getInt());
        assertEquals(65535, binary.getInt()); assertEquals(0x80000001, binary.getInt());
        assertEquals(-1, binary.getInt());
        assertEquals(nanos ? 123456789 : 123456, binary.getInt());
        assertEquals(3, binary.getInt()); assertEquals(-1, binary.getInt());
        try (PcapReader reader = new PcapReader(output)) {
            assertEquals(header, reader.globalHeader());
            CapturedPacket actual = reader.readPacket().orElseThrow();
            assertEquals(packet.timestamp(), actual.timestamp());
            assertEquals(packet.capturedLength(), actual.capturedLength());
            assertEquals(packet.originalLength(), actual.originalLength());
            assertArrayEquals(packet.rawBytes(), actual.rawBytes());
            assertEquals(0, reader.readPacket().orElseThrow().capturedLength());
            assertTrue(reader.readPacket().isEmpty());
        }
    }

    @ParameterizedTest
    @CsvSource({"true,false", "false,false", "true,true", "false,true"})
    void emptyCaptureContainsValidHeader(boolean little, boolean nanos) throws IOException {
        Path path = temp.resolve("empty.pcap");
        try (PcapWriter ignored = new PcapWriter(path, header(little, nanos))) { }
        assertEquals(24, Files.size(path));
        try (PcapReader reader = new PcapReader(path)) {
            assertEquals(header(little, nanos), reader.globalHeader());
            assertTrue(reader.readPacket().isEmpty());
        }
    }

    @Test
    void rejectsInvalidPacketWithoutWritingPartialRecord() throws IOException {
        Path path = temp.resolve("valid.pcap");
        try (PcapWriter writer = new PcapWriter(path, header(true, false))) {
            for (CapturedPacket packet : new CapturedPacket[]{
                    new CapturedPacket(Instant.EPOCH, 2, 2, new byte[1]),
                    new CapturedPacket(Instant.EPOCH, 1, 0, new byte[1]),
                    new CapturedPacket(Instant.EPOCH, 65536, 65536, new byte[65536]),
                    new CapturedPacket(Instant.EPOCH, 1, 0x100000000L, new byte[1]),
                    new CapturedPacket(Instant.ofEpochSecond(-1), 0, 0, new byte[0]),
                    new CapturedPacket(Instant.ofEpochSecond(0x100000000L), 0, 0, new byte[0]),
                    new CapturedPacket(Instant.ofEpochSecond(1, 1), 0, 0, new byte[0])}) {
                assertThrows(IOException.class, () -> writer.writePacket(packet));
            }
            assertEquals(0, writer.writtenPackets());
            writer.writePacket(new CapturedPacket(Instant.EPOCH, 0, 0, new byte[0]));
        }
        assertEquals(40, Files.size(path));
    }

    @Test
    void invalidHeaderDoesNotCreateOutput() {
        Path path = temp.resolve("invalid.pcap");
        PcapGlobalHeader invalid = new PcapGlobalHeader(ByteOrder.BIG_ENDIAN, false, 2, 4, 0, 0, 0, 1);
        assertThrows(IOException.class, () -> new PcapWriter(path, invalid));
        assertFalse(Files.exists(path));
    }

    @Test
    void invalidPathsAndExistingFilesAreSafe() throws IOException {
        Path input = temp.resolve("input.pcap");
        byte[] sentinel = new byte[]{1, 2, 3};
        Files.write(input, sentinel);
        assertThrows(IOException.class, () -> PcapWriter.validateOutputPath(input, input));
        assertThrows(IOException.class, () -> PcapWriter.validateOutputPath(input, temp.resolve("child/../input.pcap")));
        assertThrows(IOException.class, () -> new PcapWriter(input, header(true, false)));
        assertArrayEquals(sentinel, Files.readAllBytes(input));
        assertThrows(IOException.class, () -> new PcapWriter(temp, header(true, false)));
        assertThrows(IOException.class, () -> new PcapWriter(temp.resolve("missing/file.pcap"), header(true, false)));
        assertThrows(IOException.class, () -> PcapWriter.validateOutputPath(input, temp.resolve("missing/file.pcap")));
        assertThrows(IOException.class, () -> PcapWriter.validateOutputPath(temp.resolve("missing.pcap"), temp.resolve("out.pcap")));
        assertThrows(IOException.class, () -> PcapWriter.validateOutputPath(temp, temp.resolve("out.pcap")));
        assertEquals(temp.resolve("new.pcap"), PcapWriter.validateOutputPath(input, temp.resolve("new.pcap")));
    }

    @Test
    void streamWriteFailureIsReportedAndPreventsFurtherWrites() throws IOException {
        OutputStream failing = new OutputStream() {
            @Override public void write(int value) throws IOException { throw new IOException("simulated disk failure"); }
        };
        PcapWriter writer = new PcapWriter(failing, header(true, false));
        CapturedPacket packet = new CapturedPacket(Instant.EPOCH, 9000, 9000, new byte[9000]);
        assertThrows(IOException.class, () -> writer.writePacket(packet));
        assertEquals(0, writer.writtenPackets());
        assertThrows(IOException.class, () -> writer.writePacket(packet));
        assertThrows(IOException.class, writer::close);
    }

    @Test
    void flushErrorsAreReportedOnClose() throws IOException {
        OutputStream failing = new OutputStream() {
            @Override public void write(int value) throws IOException { throw new IOException("simulated flush failure"); }
        };
        PcapWriter writer = new PcapWriter(failing, header(true, false));
        assertThrows(IOException.class, writer::close);
    }

    @Test
    void cannotWriteAfterCloseAndRepeatedCloseIsSafe() throws IOException {
        PcapWriter writer = new PcapWriter(new ByteArrayOutputStream(), header(true, false));
        writer.close(); writer.close();
        assertThrows(IOException.class, () -> writer.writePacket(new CapturedPacket(Instant.EPOCH, 0, 0, new byte[0])));
    }
}
