package com.dpiengine.api;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

/** Request-owned files; attempt every deletion and let try-with-resources preserve primary failures. */
final class Workspace implements AutoCloseable {
    @FunctionalInterface interface Deleter { void delete(Path path) throws IOException; }
    final Path directory, input, output;
    private final Deleter deleter;

    Workspace(Path directory) { this(directory, Files::deleteIfExists); }
    Workspace(Path directory, Deleter deleter) {
        this.directory = directory;
        input = directory.resolve("input.pcap");
        output = directory.resolve("filtered.pcap");
        this.deleter = deleter;
    }

    @Override public void close() throws IOException {
        IOException failure = null;
        for (Path path : new Path[]{output, input, directory}) {
            try { deleter.delete(path); }
            catch (IOException e) { if (failure == null) failure = e; else failure.addSuppressed(e); }
        }
        if (failure != null) throw failure;
    }
}
