package com.dpiengine.api;

import com.dpiengine.pcap.PcapReader;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.util.unit.DataSize;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@Timeout(20)
class DpiServiceHardeningTest {
    @TempDir Path temp;
    private ApiProperties properties(int concurrent, int totalWorkers) {
        return new ApiProperties(DataSize.ofMegabytes(25), temp, concurrent, 8, totalWorkers, 100000, 10000, 262144);
    }
    private MockMultipartFile file() throws IOException {
        return new MockMultipartFile("file", "../../input.pcap", "application/octet-stream",
                Files.readAllBytes(Path.of("../test_dpi.pcap")));
    }
    private void emptyWorkspace() throws IOException {
        try (var paths = Files.list(temp)) { assertEquals(0, paths.count()); }
    }
    private MockMvc mvc(DpiService service) {
        return MockMvcBuilders.standaloneSetup(new DpiController(service)).setControllerAdvice(new ApiErrors()).build();
    }

    @ParameterizedTest @ValueSource(booleans={false, true})
    void saturatedRequestsReturn429AndBothPermitBudgetsRecover(boolean workerSaturation) throws Exception {
        CountDownLatch reading = new CountDownLatch(1), release = new CountDownLatch(1);
        AtomicBoolean first = new AtomicBoolean(true);
        var service = new DpiService(properties(workerSaturation ? 2 : 1, workerSaturation ? 4 : 8), (path, max) -> {
            if (first.getAndSet(false)) {
                reading.countDown();
                try {
                    if (!release.await(5, TimeUnit.SECONDS)) throw new IOException("test release timed out");
                } catch (InterruptedException e) { Thread.currentThread().interrupt(); throw new IOException(e); }
            }
            return new PcapReader(path, max);
        });
        MockMvc mvc = mvc(service);
        var options = new MockMultipartFile("options", "", "application/json", "{\"workers\":4}".getBytes(java.nio.charset.StandardCharsets.UTF_8));
        try (var callers = Executors.newSingleThreadExecutor()) {
            var inFlight = callers.submit(() -> mvc.perform(multipart("/api/v1/dpi/analyze").file(file()).file(options))
                    .andExpect(status().isOk()).andReturn());
            try {
                assertTrue(reading.await(5, TimeUnit.SECONDS));
                for (String endpoint : List.of("analyze", "filter")) {
                    mvc.perform(multipart("/api/v1/dpi/" + endpoint).file(file()))
                            .andExpect(status().isTooManyRequests())
                            .andExpect(jsonPath("$.detail").value(org.hamcrest.Matchers.containsString(
                                    workerSaturation ? "worker budget" : "Concurrent processing")));
                }
            } finally { release.countDown(); }
            inFlight.get(5, TimeUnit.SECONDS);
        }
        mvc.perform(multipart("/api/v1/dpi/analyze").file(file()).file(options)).andExpect(status().isOk());
        emptyWorkspace();
    }

    @Test void genuineValidationReadFailureIs500AndPermitsRecover() throws Exception {
        AtomicBoolean fail = new AtomicBoolean(true);
        var service = new DpiService(properties(1, 8), (path, max) -> {
            if (fail.getAndSet(false)) throw new IOException("injected storage read failure");
            return new PcapReader(path, max);
        });
        MockMvc mvc = mvc(service);
        mvc.perform(multipart("/api/v1/dpi/filter").file(file())).andExpect(status().isInternalServerError());
        emptyWorkspace();
        mvc.perform(multipart("/api/v1/dpi/filter").file(file())).andExpect(status().isOk());
        emptyWorkspace();
    }

    @Test void failedTransferCleansWorkspaceAndReleasesPermits() throws Exception {
        var service = new DpiService(properties(1, 8));
        var upload = new MockMultipartFile("file", new byte[]{1}) {
            @Override public void transferTo(Path destination) throws IOException {
                Files.write(destination, new byte[]{1});
                throw new IOException("injected transfer failure");
            }
        };
        assertEquals("injected transfer failure", assertThrows(IOException.class,
                () -> service.process(upload, DpiOptions.defaults(), null)).getMessage());
        emptyWorkspace();
        assertEquals(12, service.process(file(), DpiOptions.defaults(), null).totalPackets());
        emptyWorkspace();
    }

    @Test void failedDownloadReleasesFileHandlesWorkspaceAndPermits() throws Exception {
        var service = new DpiService(properties(1, 8));
        IOException disconnected = new IOException("client disconnected");
        var error = assertThrows(IOException.class, () -> service.process(file(), DpiOptions.defaults(), (path, stats) -> {
            assertTrue(Files.size(path) > 0);
            try (var input = Files.newInputStream(path)) {
                input.transferTo(new java.io.OutputStream() {
                    @Override public void write(int value) throws IOException { throw disconnected; }
                });
            }
        }));
        assertSame(disconnected, error);
        emptyWorkspace();
        assertEquals(12, service.process(file(), DpiOptions.defaults(), null).totalPackets());
        emptyWorkspace();
    }

    @Test void cleanupAttemptsAllPathsAndPreservesPrimaryFailure() {
        var attempted = new ArrayList<Path>();
        IOException primary = new IOException("processing failed");
        var error = assertThrows(IOException.class, () -> {
            try (var workspace = new Workspace(temp, path -> {
                attempted.add(path);
                throw new IOException("delete failed: " + path.getFileName());
            })) { throw primary; }
        });
        assertSame(primary, error);
        assertEquals(List.of(temp.resolve("filtered.pcap"), temp.resolve("input.pcap"), temp), attempted);
        assertEquals(1, error.getSuppressed().length);
        assertEquals(2, error.getSuppressed()[0].getSuppressed().length);
    }

    @Test void cleanupFailureWithoutPrimaryIsReported() {
        var error = assertThrows(IOException.class, () -> {
            try (var workspace = new Workspace(temp, path -> { throw new IOException("delete failed"); })) { }
        });
        assertEquals("delete failed", error.getMessage());
        assertEquals(2, error.getSuppressed().length);
    }
}
