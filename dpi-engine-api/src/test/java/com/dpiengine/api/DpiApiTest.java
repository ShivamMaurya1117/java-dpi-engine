package com.dpiengine.api;

import com.dpiengine.engine.DpiEngine;
import com.dpiengine.engine.DpiEngineConfig;
import com.dpiengine.inspect.AppType;
import com.dpiengine.rules.RuleSet;
import com.dpiengine.pcap.PcapReader;
import com.dpiengine.pcap.PcapGlobalHeader;
import com.dpiengine.pcap.PcapWriter;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.http.*;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.util.LinkedMultiValueMap;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.UUID;
import java.util.concurrent.Executors;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.time.Instant;
import com.dpiengine.pcap.CapturedPacket;
import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest(webEnvironment=SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties={"spring.servlet.multipart.max-file-size=16KB", "spring.servlet.multipart.max-request-size=20KB",
                "dpi.api.max-packets=100", "dpi.api.max-flows=50", "dpi.api.max-packet-bytes=8192"})
class DpiApiTest {
    private static final Path WORK = Path.of("target", "request-tests-" + UUID.randomUUID()).toAbsolutePath();
    private static final String DEMO = "{\"workers\":4,\"blockedApplications\":[\"DNS\"],\"blockedDomains\":[\"example.org\"],\"blockedIpv4Addresses\":[\"203.0.113.99\"]}";
    @TempDir Path temp;
    @Autowired TestRestTemplate http;
    @Autowired ObjectMapper json;
    @DynamicPropertySource static void properties(DynamicPropertyRegistry registry) {
        registry.add("dpi.api.temp-directory", () -> WORK.toString());
    }
    private byte[] sample() throws Exception { return Files.readAllBytes(Path.of("../test_dpi.pcap")); }
    private ResponseEntity<byte[]> upload(String endpoint, byte[] bytes, String options) {
        var parts = new LinkedMultiValueMap<String, Object>();
        parts.add("file", new ByteArrayResource(bytes) {
            @Override public String getFilename() { return "../../test_dpi.pcap"; }
        });
        if (options != null) {
            HttpHeaders headers = new HttpHeaders(); headers.setContentType(MediaType.APPLICATION_JSON);
            parts.add("options", new HttpEntity<>(options, headers));
        }
        HttpHeaders headers = new HttpHeaders(); headers.setContentType(MediaType.MULTIPART_FORM_DATA);
        return http.postForEntity("/api/v1/dpi/" + endpoint, new HttpEntity<>(parts, headers), byte[].class);
    }
    private JsonNode statistics(ResponseEntity<byte[]> response) throws Exception {
        assertEquals(HttpStatus.OK, response.getStatusCode());
        return json.readTree(response.getBody());
    }
    @AfterEach void noTemporaryFilesRemain() throws Exception {
        if (Files.exists(WORK)) try (var entries = Files.list(WORK)) { assertEquals(0, entries.count()); }
    }

    @Test void healthSwaggerAndOpenApiAreAvailable() throws Exception {
        assertEquals("UP", http.getForObject("/actuator/health", JsonNode.class).path("status").asText());
        assertEquals(HttpStatus.OK, http.getForEntity("/swagger-ui/index.html", String.class).getStatusCode());
        JsonNode specification = http.getForObject("/v3/api-docs", JsonNode.class);
        assertTrue(specification.path("paths").has("/api/v1/dpi/analyze"));
        assertTrue(specification.path("paths").has("/api/v1/dpi/filter"));
        assertEquals("binary", specification.path("paths").path("/api/v1/dpi/filter").path("post")
                .path("responses").path("200").path("content").path("application/vnd.tcpdump.pcap")
                .path("schema").path("format").asText());
        for (String endpoint : new String[]{"analyze", "filter"}) {
            JsonNode multipart = specification.path("paths").path("/api/v1/dpi/" + endpoint)
                    .path("post").path("requestBody").path("content").path("multipart/form-data");
            assertEquals("application/json", multipart.path("encoding").path("options").path("contentType").asText());
            JsonNode schema = multipart.path("schema");
            if (schema.has("$ref")) schema = specification.at(schema.path("$ref").asText().substring(1));
            assertEquals("binary", schema.path("properties").path("file").path("format").asText());
            assertEquals("#/components/schemas/DpiOptions", schema.path("properties").path("options").path("$ref").asText());
            assertFalse(schema.path("required").toString().contains("options"));
        }
    }

    @ParameterizedTest @ValueSource(strings={"analyze", "filter"})
    void acceptanceOptionsWithOneWorker(String endpoint) throws Exception {
        var response = upload(endpoint, sample(), DEMO.replace("\"workers\":4", "\"workers\":1"));
        assertEquals(HttpStatus.OK, response.getStatusCode());
        if (endpoint.equals("analyze")) {
            JsonNode stats = statistics(response);
            assertEquals(12, stats.path("totalPackets").asInt());
            assertEquals(6, stats.path("allowedPackets").asInt());
            assertEquals(6, stats.path("blockedPackets").asInt());
        } else {
            assertEquals("12", response.getHeaders().getFirst("X-DPI-Total-Packets"));
            assertEquals("6", response.getHeaders().getFirst("X-DPI-Allowed-Packets"));
            assertEquals("6", response.getHeaders().getFirst("X-DPI-Blocked-Packets"));
            Path download = temp.resolve("download.pcap");
            Files.write(download, response.getBody());
            int count = 0;
            try (PcapReader reader = new PcapReader(download)) {
                while (reader.readPacket().isPresent()) count++;
            }
            assertEquals(6, count);
        }
    }

    @ParameterizedTest @CsvSource({"analyze,{}", "filter,{}", "analyze,''", "filter,''"})
    void emptyOptionsUseDefaults(String endpoint, String options) throws Exception {
        var response = upload(endpoint, sample(), options);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        if (endpoint.equals("analyze")) {
            assertEquals(12, statistics(response).path("allowedPackets").asInt());
        } else assertArrayEquals(sample(), response.getBody());
    }

    @Test void analysisReturnsCoreStatistics() throws Exception {
        JsonNode stats = statistics(upload("analyze", sample(), null));
        assertEquals(12, stats.path("totalPackets").asInt());
        assertEquals(12, stats.path("parsedPackets").asInt());
        assertEquals(0, stats.path("skippedPackets").asInt());
        assertEquals(8, stats.path("tcpPackets").asInt());
        assertEquals(4, stats.path("udpPackets").asInt());
        assertEquals(8, stats.path("uniqueFlows").asInt());
        assertEquals(12, stats.path("allowedPackets").asInt());
        assertEquals(0, stats.path("blockedPackets").asInt());
        assertEquals(0, stats.path("writtenPackets").asInt());
        assertEquals(2, stats.path("applicationDistribution").path("HTTPS").asInt());
        assertTrue(stats.path("blockingReasons").isArray());
        assertTrue(stats.path("processingDurationMs").asDouble() >= 0);
    }

    @Test void analysisWithRulesReportsReasonsWithoutWriting() throws Exception {
        JsonNode stats = statistics(upload("analyze", sample(), DEMO));
        assertEquals(6, stats.path("allowedPackets").asInt());
        assertEquals(6, stats.path("blockedPackets").asInt());
        assertEquals(3, stats.path("blockingReasons").size());
        assertEquals(0, stats.path("writtenPackets").asInt());
    }

    @Test void filterWithoutRulesPreservesInputByteForByte() throws Exception {
        byte[] input = sample();
        var response = upload("filter", input, null);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertArrayEquals(input, response.getBody());
        assertEquals("12", response.getHeaders().getFirst("X-DPI-Allowed-Packets"));
        assertEquals("0", response.getHeaders().getFirst("X-DPI-Blocked-Packets"));
        assertTrue(response.getHeaders().getFirst("Content-Disposition").contains("filtered.pcap"));
    }

    @Test void demoDownloadIsExactlyCoreFilteredCapture() throws Exception {
        var response = upload("filter", sample(), DEMO);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals("6", response.getHeaders().getFirst("X-DPI-Allowed-Packets"));
        assertEquals("6", response.getHeaders().getFirst("X-DPI-Blocked-Packets"));
        Path core = temp.resolve("core-filtered.pcap");
        RuleSet rules = RuleSet.builder().blockApplication(AppType.DNS).blockDomain("example.org").blockIpv4("203.0.113.99").build();
        new DpiEngine().process(new DpiEngineConfig(Path.of("../test_dpi.pcap"), core, rules, 4));
        assertArrayEquals(Files.readAllBytes(core), response.getBody());
    }

    @ParameterizedTest @ValueSource(strings={"{\"workers\":0}", "{\"workers\":65}", "{\"workers\":-1}",
            "{\"blockedApplications\":[\"NOT_AN_APP\"]}", "{\"blockedDomains\":[\"*.youtube.com\"]}",
            "{\"blockedIpv4Addresses\":[\"999.1.2.3\"]}", "{\"blockedDomains\":[null]}",
            "{\"workers\":\"invalid\"}", "{\"unknownOption\":1}", "invalid json"})
    void rejectsMalformedOptions(String options) throws Exception {
        for (String endpoint : new String[]{"analyze", "filter"}) {
            var response = upload(endpoint, sample(), options);
            assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
            assertEquals(400, json.readTree(response.getBody()).path("status").asInt());
        }
    }

    @Test void rejectsEmptyInvalidPcapngAndTruncatedUploads() throws Exception {
        for (byte[] data : new byte[][]{new byte[0], new byte[]{1, 2, 3}, new byte[]{10, 13, 13, 10}, Arrays.copyOf(sample(), 100)}) {
            var response = upload("filter", data, null);
            assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
            assertEquals(400, json.readTree(response.getBody()).path("status").asInt());
        }
    }

    @ParameterizedTest
    @CsvSource({"analyze,0", "filter,0", "analyze,101", "filter,101",
            "analyze,113", "filter,113", "analyze,4294967295", "filter,4294967295"})
    void rejectsUnsupportedLinkTypesWithRulesAndCleansWorkspace(String endpoint, long linkType) throws Exception {
        Path input = temp.resolve("unsupported.pcap");
        // Reuse the PCAP reader/writer so all framing remains valid apart from the unsupported link type.
        try (PcapReader reader = new PcapReader(Path.of("../test_dpi.pcap"))) {
            var header = reader.globalHeader();
            var unsupported = new PcapGlobalHeader(header.byteOrder(), header.nanosecondResolution(),
                    header.versionMajor(), header.versionMinor(), header.thisZone(), header.sigFigs(),
                    header.snapLength(), linkType);
            try (PcapWriter writer = new PcapWriter(input, unsupported)) {
                var packet = reader.readPacket();
                while (packet.isPresent()) {
                    writer.writePacket(packet.orElseThrow());
                    packet = reader.readPacket();
                }
            }
        }
        for (String options : new String[]{null, "{}", DEMO}) {
            var response = upload(endpoint, Files.readAllBytes(input), options);
            assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
            JsonNode problem = json.readTree(response.getBody());
            assertEquals(400, problem.path("status").asInt());
            assertEquals("Unsupported PCAP link type " + linkType
                    + "; Ethernet (link type 1, DLT_EN10MB) is required. Upload an Ethernet PCAP capture.",
                    problem.path("detail").asText());
            assertNull(response.getHeaders().getFirst("Content-Disposition"));
            noTemporaryFilesRemain();
        }
    }

    @Test void uploadSizeIsEnforcedByRealServletContainer() {
        var response = upload("analyze", new byte[17 * 1024], null);
        assertEquals(HttpStatus.PAYLOAD_TOO_LARGE, response.getStatusCode());
    }

    @Test void simultaneousSameFilenameRequestsHaveIndependentStateAndCleanup() throws Exception {
        byte[] sample = sample();
        try (var callers = Executors.newFixedThreadPool(2)) {
            var noRules = callers.submit(() -> upload("analyze", sample, "{\"workers\":8}"));
            var demo = callers.submit(() -> upload("analyze", sample, DEMO));
            assertEquals(12, statistics(noRules.get()).path("allowedPackets").asInt());
            assertEquals(6, statistics(demo.get()).path("allowedPackets").asInt());
        }
    }

    @Test void temporaryStorageFailureReturns500AndDoesNotLeak() throws Exception {
        Files.createDirectories(WORK);
        Files.delete(WORK);
        Files.writeString(WORK, "not a directory");
        try { assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, upload("analyze", sample(), null).getStatusCode()); }
        finally { Files.delete(WORK); Files.createDirectories(WORK); }
    }

    @ParameterizedTest @ValueSource(strings={"{\"workers\":\"2\"}", "{\"workers\":2.0}", "{\"workers\":1.5}",
            "{\"workers\":true}", "{\"workers\":\"\"}", "{\"workers\":9}",
            "{\"blockedApplications\":[1]}", "{\"blockedApplications\":[true]}", "{\"blockedApplications\":[null]}",
            "{\"blockedDomains\":[1.5]}", "{\"blockedDomains\":[false]}", "{\"blockedDomains\":[\"\"]}",
            "{\"blockedIpv4Addresses\":[1234]}", "{\"blockedIpv4Addresses\":[true]}",
            "{\"blockedIpv4Addresses\":[null]}", "{\"blockedApplications\":\"YOUTUBE\"}",
            "{\"blockedIpv4Addresses\":[\"01.2.3.4\"]}", "{\"blockedDomains\":[{}]}"})
    void rejectsCoercionAndInvalidRuleEntries(String options) throws Exception {
        for (String endpoint : new String[]{"analyze", "filter"}) {
            var response = upload(endpoint, sample(), options);
            assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
            assertFalse(json.readTree(response.getBody()).path("detail").asText().isBlank());
            noTemporaryFilesRemain();
        }
    }

    @ParameterizedTest @ValueSource(strings={"{}", "{\"workers\":null}", "{\"workers\":1}", "{\"workers\":8}",
            "{\"blockedApplications\":null,\"blockedDomains\":[],\"blockedIpv4Addresses\":null}"})
    void strictOptionsRetainDocumentedDefaults(String options) throws Exception {
        assertEquals(12, statistics(upload("analyze", sample(), options)).path("allowedPackets").asInt());
        var download = upload("filter", sample(), options);
        assertEquals(HttpStatus.OK, download.getStatusCode());
        assertArrayEquals(sample(), download.getBody());
    }

    @ParameterizedTest @ValueSource(strings={"blockedApplications", "blockedDomains", "blockedIpv4Addresses"})
    void rejectsRuleListsAbove256Entries(String field) throws Exception {
        String value = field.equals("blockedApplications") ? "HTTP" : field.equals("blockedDomains") ? "example.com" : "1.2.3.4";
        String options = json.writeValueAsString(java.util.Map.of(field, java.util.Collections.nCopies(257, value)));
        for (String endpoint : new String[]{"analyze", "filter"}) {
            assertEquals(HttpStatus.BAD_REQUEST, upload(endpoint, sample(), options).getStatusCode());
        }
    }

    @ParameterizedTest @ValueSource(strings={"blockedApplications", "blockedDomains", "blockedIpv4Addresses"})
    void acceptsRuleListsAt256EntryBoundary(String field) throws Exception {
        String value = field.equals("blockedApplications") ? "HTTP" : field.equals("blockedDomains") ? "example.com" : "1.2.3.4";
        String options = json.writeValueAsString(java.util.Map.of(field, java.util.Collections.nCopies(256, value)));
        for (String endpoint : new String[]{"analyze", "filter"}) {
            assertEquals(HttpStatus.OK, upload(endpoint, sample(), options).getStatusCode());
        }
    }

    @ParameterizedTest @ValueSource(strings={"analyze", "filter"})
    void missingFileAndUnsupportedMediaTypesAreExplicitlyRejected(String endpoint) {
        String url = "/api/v1/dpi/" + endpoint;
        var parts = new LinkedMultiValueMap<String, Object>();
        var optionsHeaders = new HttpHeaders(); optionsHeaders.setContentType(MediaType.APPLICATION_JSON);
        parts.add("options", new HttpEntity<>("{}", optionsHeaders));
        var multipart = new HttpHeaders(); multipart.setContentType(MediaType.MULTIPART_FORM_DATA);
        assertEquals(HttpStatus.BAD_REQUEST, http.postForEntity(url, new HttpEntity<>(parts, multipart), byte[].class).getStatusCode());
        var jsonHeaders = new HttpHeaders(); jsonHeaders.setContentType(MediaType.APPLICATION_JSON);
        assertEquals(HttpStatus.UNSUPPORTED_MEDIA_TYPE,
                http.postForEntity(url, new HttpEntity<>("{}", jsonHeaders), byte[].class).getStatusCode());
        parts.add("file", new ByteArrayResource(new byte[]{1}) { @Override public String getFilename() { return "input.pcap"; } });
        var textHeaders = new HttpHeaders(); textHeaders.setContentType(MediaType.TEXT_PLAIN);
        parts.set("options", new HttpEntity<>("{}", textHeaders));
        assertEquals(HttpStatus.UNSUPPORTED_MEDIA_TYPE,
                http.postForEntity(url, new HttpEntity<>(parts, multipart), byte[].class).getStatusCode());
    }

    @ParameterizedTest @ValueSource(strings={"analyze", "filter"})
    void totalMultipartLimitIsEnforcedEvenWithSmallFile(String endpoint) throws Exception {
        var parts = new LinkedMultiValueMap<String, Object>();
        parts.add("file", new ByteArrayResource(sample()) { @Override public String getFilename() { return "input.pcap"; } });
        parts.add("padding", "x".repeat(15 * 1024));
        // Exceed 20 KiB overall even with the smaller deterministic fixture;
        // keep each individual part below the 16 KiB file/part ceiling.
        parts.add("padding2", "y".repeat(5 * 1024));
        var headers = new HttpHeaders(); headers.setContentType(MediaType.MULTIPART_FORM_DATA);
        assertEquals(HttpStatus.PAYLOAD_TOO_LARGE, http.postForEntity("/api/v1/dpi/" + endpoint,
                new HttpEntity<>(parts, headers), byte[].class).getStatusCode());
    }

    private byte[] budgetCapture(String budget) throws Exception {
        Path input = temp.resolve("budget.pcap");
        try (PcapWriter writer = new PcapWriter(input,
                new PcapGlobalHeader(ByteOrder.LITTLE_ENDIAN, false, 2, 4, 0, 0, 65535, 1))) {
            int records = budget.equals("record") ? 101 : budget.equals("flow") ? 51 : 1;
            for (int i = 0; i < records; i++) {
                byte[] data = new byte[budget.equals("record") ? 0 : budget.equals("flow") ? 54 : 8193];
                if (budget.equals("flow")) ByteBuffer.wrap(data).putShort(12, (short) 0x0800).put(14, (byte) 0x45)
                        .putShort(16, (short) 40).put(23, (byte) 6).putInt(26, 0xc0a80102).putInt(30, 0x08080808)
                        .putShort(34, (short) (10000 + i)).putShort(36, (short) 443).put(46, (byte) 0x50);
                writer.writePacket(new CapturedPacket(Instant.EPOCH, data.length, data.length, data));
            }
        }
        return Files.readAllBytes(input);
    }

    @ParameterizedTest @CsvSource({"analyze,record,1", "filter,record,4", "analyze,flow,1", "filter,flow,4",
            "analyze,captured-byte,1", "filter,captured-byte,4"})
    void processingBudgetReturns413AndRecovers(String endpoint, String budget, int workers) throws Exception {
        var response = upload(endpoint, budgetCapture(budget), "{\"workers\":" + workers + "}");
        assertEquals(HttpStatus.PAYLOAD_TOO_LARGE, response.getStatusCode());
        assertTrue(json.readTree(response.getBody()).path("detail").asText().contains(budget + " budget"));
        assertNull(response.getHeaders().getFirst("Content-Disposition"));
        noTemporaryFilesRemain();
        assertEquals(HttpStatus.OK, upload(endpoint, sample(), DEMO).getStatusCode());
    }
}
