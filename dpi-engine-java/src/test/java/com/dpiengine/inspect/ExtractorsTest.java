package com.dpiengine.inspect;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Optional;
import static org.junit.jupiter.api.Assertions.*;
import static com.dpiengine.inspect.InspectionFixtures.*;

class ExtractorsTest {
    private final TlsSniExtractor tls = new TlsSniExtractor();
    private final HttpHostExtractor http = new HttpHostExtractor();
    private final DnsQueryExtractor dns = new DnsQueryExtractor();

    @Test
    void extractsTlsSniFromBoundedSlice() {
        byte[] payload = tls("WWW.Google.COM");
        byte[] wrapped = new byte[payload.length + 20];
        System.arraycopy(payload, 0, wrapped, 7, payload.length);
        assertEquals(Optional.of("www.google.com"), tls.extract(wrapped, 7, payload.length));
        assertTrue(tls.extract(wrapped, 7, payload.length - 1).isEmpty());
    }

    @Test
    void rejectsEveryTlsTruncation() {
        byte[] payload = tls("example.org");
        for (int i = 0; i < payload.length; i++) assertTrue(tls.extract(payload, 0, i).isEmpty(), "length=" + i);
    }

    @ParameterizedTest
    @CsvSource({"0,23", "1,2", "5,2", "43,33", "44,255", "45,1", "48,0", "50,255", "54,255", "56,255", "59,255"})
    void rejectsMalformedTlsFields(int offset, int value) {
        byte[] payload = tls("example.org");
        payload[offset] = (byte) value;
        assertTrue(tls.extract(payload, 0, payload.length).isEmpty());
    }

    @Test
    void respectsRecordAndHandshakeBoundsEvenWhenCaptureContainsMoreBytes() {
        for (int offset : new int[]{3, 7}) {
            byte[] payload = tls("example.org");
            ByteBuffer.wrap(payload).putShort(offset, (short) 4);
            assertTrue(tls.extract(payload, 0, payload.length).isEmpty());
        }
    }

    @Test
    void validatesExtensionsFollowingSni() {
        byte[] original = tls("example.org");
        byte[] payload = Arrays.copyOf(original, original.length + 4);
        ByteBuffer b = ByteBuffer.wrap(payload);
        b.putShort(3, (short) (payload.length - 5)).putShort(7, (short) (payload.length - 9));
        b.putShort(50, (short) (payload.length - 52));
        b.putShort(original.length, (short) 42).putShort(original.length + 2, (short) 1);
        assertTrue(tls.extract(payload, 0, payload.length).isEmpty());
        b.putShort(original.length + 2, (short) 0);
        assertEquals(Optional.of("example.org"), tls.extract(payload, 0, payload.length));
    }

    @Test
    void absentSniIsSafe() {
        byte[] payload = tls("example.org");
        ByteBuffer.wrap(payload).putShort(52, (short) 42);
        assertTrue(tls.extract(payload, 0, payload.length).isEmpty());
    }

    @ParameterizedTest
    @ValueSource(strings = {"bad host.org", "bad..org", "-bad.org", "bad_.org", "bad.org/", ""})
    void rejectsInvalidSniHostnames(String name) {
        byte[] payload = tls(name);
        assertTrue(tls.extract(payload, 0, payload.length).isEmpty());
    }

    @Test
    void extractsHttpHostCaseInsensitivelyAndRemovesPort() {
        byte[] payload = ascii("POST /abc HTTP/1.1\r\nhOsT:\tWWW.GitHub.COM.:8080 \r\nX-Test: value\r\n\r\nbody");
        assertEquals(Optional.of("www.github.com"), http.extract(payload, 0, payload.length));
    }

    @Test
    void rejectsEveryHttpHeaderTruncation() {
        byte[] payload = http("example.org");
        for (int i = 0; i < payload.length; i++) assertTrue(http.extract(payload, 0, i).isEmpty());
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "GET / HTTP/1.1\r\nX-Host: github.com\r\n\r\nHost: google.com\r\n",
            "HTTP/1.1 200 OK\r\nHost: github.com\r\n\r\n",
            "GET / HTTP/1.1\r\nHost: github.com\r\nHost: google.com\r\n\r\n",
            "GET / HTTP/1.1\r\n Host: github.com\r\n\r\n",
            "GET / HTTP/1.1\r\nHost: example.org:99999\r\n\r\n",
            "GET / HTTP/1.1\r\nHost: example.org:abc\r\n\r\n",
            "GET / HTTP/1.1\r\nHost: bad host.org\r\n\r\n"})
    void rejectsMalformedHttpAndNeverReadsBodyAsHost(String request) {
        byte[] payload = ascii(request);
        assertTrue(http.extract(payload, 0, payload.length).isEmpty());
    }

    @Test
    void extractsDnsQuery() {
        byte[] payload = dns("WWW.Google.COM");
        assertEquals(Optional.of("www.google.com"), dns.extract(payload, 0, payload.length));
    }

    @Test
    void rejectsEveryDnsTruncation() {
        byte[] payload = dns("example.org");
        for (int i = 0; i < payload.length; i++) assertTrue(dns.extract(payload, 0, i).isEmpty());
    }

    @ParameterizedTest
    @CsvSource({"2,128", "2,8", "5,0", "5,2", "12,64", "12,192", "13,255"})
    void rejectsMalformedDnsAndCompressionPointers(int offset, int value) {
        byte[] payload = dns("example.org");
        payload[offset] = (byte) value;
        assertTrue(dns.extract(payload, 0, payload.length).isEmpty());
    }

    @Test
    void dnsRequiresTerminatorAndQuestionTypeAndClass() {
        byte[] payload = dns("example.org");
        for (int offset : new int[]{payload.length - 4, payload.length - 2}) {
            byte[] mutated = payload.clone();
            ByteBuffer.wrap(mutated).putShort(offset, (short) 0);
            assertTrue(dns.extract(mutated, 0, mutated.length).isEmpty());
        }
        payload[payload.length - 5] = 1;
        assertTrue(dns.extract(payload, 0, payload.length).isEmpty());
    }

    @Test
    void allExtractorsSafelyRejectInvalidSlices() {
        byte[] payload = new byte[4];
        for (int[] bounds : new int[][]{{-1, 1}, {0, -1}, {5, 0}, {1, Integer.MAX_VALUE}}) {
            assertTrue(tls.extract(payload, bounds[0], bounds[1]).isEmpty());
            assertTrue(http.extract(payload, bounds[0], bounds[1]).isEmpty());
            assertTrue(dns.extract(payload, bounds[0], bounds[1]).isEmpty());
        }
    }
}
