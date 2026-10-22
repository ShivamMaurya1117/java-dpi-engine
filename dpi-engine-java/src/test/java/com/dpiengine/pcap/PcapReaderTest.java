package com.dpiengine.pcap;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import java.io.EOFException;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Arrays;
import static org.junit.jupiter.api.Assertions.*;

class PcapReaderTest {
    @TempDir Path temp;

    private byte[] fixture(boolean little, boolean nanos, int fraction, int captured, int original) {
        return ByteBuffer.allocate(43)
                .order(little ? ByteOrder.LITTLE_ENDIAN : ByteOrder.BIG_ENDIAN)
                .putInt(nanos ? 0xa1b23c4d : 0xa1b2c3d4)
                .putShort((short) 2).putShort((short) 4)
                .putInt(0).putInt(0).putInt(65535).putInt(1)
                .putInt(-1).putInt(fraction).putInt(captured).putInt(original)
                .put(new byte[]{1, 2, 3}).array();
    }

    private Path write(byte[] bytes) throws IOException {
        Path path = temp.resolve("capture.pcap");
        Files.write(path, bytes);
        return path;
    }

    @ParameterizedTest
    @CsvSource({"true,false", "false,false", "true,true", "false,true"})
    void readsBothByteOrdersAndTimestampResolutions(boolean little, boolean nanos) throws IOException {
        try (PcapReader reader = new PcapReader(write(fixture(little, nanos, 123456, 3, 9)))) {
            PcapGlobalHeader header = reader.globalHeader();
            assertEquals(little ? ByteOrder.LITTLE_ENDIAN : ByteOrder.BIG_ENDIAN, header.byteOrder());
            assertEquals(nanos, header.nanosecondResolution());
            assertEquals(2, header.versionMajor());
            assertEquals(4, header.versionMinor());
            assertEquals(65535, header.snapLength());
            assertEquals(1, header.network());
            CapturedPacket packet = reader.readPacket().orElseThrow();
            assertEquals(Instant.ofEpochSecond(0xffffffffL, nanos ? 123456 : 123456000), packet.timestamp());
            assertEquals(3, packet.capturedLength());
            assertEquals(9, packet.originalLength());
            assertArrayEquals(new byte[]{1, 2, 3}, packet.rawBytes());
            packet.rawBytes()[0] = 99;
            assertEquals(1, packet.rawBytes()[0]);
            assertTrue(reader.readPacket().isEmpty());
            assertTrue(reader.readPacket().isEmpty());
        }
    }

    @Test
    void readsMultiplePacketsIncludingZeroLength() throws IOException {
        byte[] first = fixture(true, false, 0, 3, 3);
        ByteBuffer data = ByteBuffer.allocate(59).order(ByteOrder.LITTLE_ENDIAN);
        data.put(first).putInt(1).putInt(0).putInt(0).putInt(0);
        try (PcapReader reader = new PcapReader(write(data.array()))) {
            assertEquals(3, reader.readPacket().orElseThrow().rawBytes().length);
            assertEquals(0, reader.readPacket().orElseThrow().rawBytes().length);
            assertTrue(reader.readPacket().isEmpty());
        }
    }

    @Test
    void headerOnlyIsCleanEof() throws IOException {
        try (PcapReader reader = new PcapReader(write(Arrays.copyOf(fixture(true, false, 0, 3, 3), 24)))) {
            assertTrue(reader.readPacket().isEmpty());
        }
    }

    @Test
    void rejectsEveryTruncatedGlobalHeader() throws IOException {
        byte[] valid = fixture(true, false, 0, 3, 3);
        for (int length = 0; length < 24; length++) {
            Path path = write(Arrays.copyOf(valid, length));
            assertThrows(EOFException.class, () -> new PcapReader(path));
        }
    }

    @Test
    void rejectsEveryTruncatedPacketAndCannotResume() throws IOException {
        byte[] valid = fixture(true, false, 0, 3, 3);
        for (int length = 25; length < valid.length; length++) {
            try (PcapReader reader = new PcapReader(write(Arrays.copyOf(valid, length)))) {
                assertThrows(EOFException.class, reader::readPacket);
                assertThrows(IOException.class, reader::readPacket);
            }
        }
    }

    @ParameterizedTest
    @CsvSource({"1000000,3,3", "0,4,3", "0,65536,65536", "0,-1,-1", "0,67108865,67108865"})
    void rejectsInvalidTimestampOrLengths(int fraction, int captured, int original) throws IOException {
        byte[] bytes = fixture(true, false, fraction, captured, original);
        // Permit the large lengths in the global header to exercise the allocation ceiling.
        if (captured > 65536 || captured < 0) ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN).putInt(16, -1);
        try (PcapReader reader = new PcapReader(write(bytes))) {
            assertThrows(IOException.class, reader::readPacket);
        }
    }

    @Test
    void rejectsInvalidNanosecondFraction() throws IOException {
        try (PcapReader reader = new PcapReader(write(fixture(false, true, 1_000_000_000, 3, 3)))) {
            assertThrows(IOException.class, reader::readPacket);
        }
    }

    @Test
    void rejectsUnsupportedMagicVersionAndZeroSnapshot() throws IOException {
        for (int offset : new int[]{0, 4, 16}) {
            byte[] bytes = fixture(true, false, 0, 3, 3);
            ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN).putInt(offset, 0);
            Path path = write(bytes);
            assertThrows(IOException.class, () -> new PcapReader(path));
        }
    }

    @Test
    void cannotReadAfterClose() throws IOException {
        PcapReader reader = new PcapReader(write(fixture(true, false, 0, 3, 3)));
        reader.close();
        assertThrows(IOException.class, reader::readPacket);
    }
}
