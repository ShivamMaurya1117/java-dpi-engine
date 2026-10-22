package com.dpiengine.pcap;

import com.dpiengine.flow.FlowTracker;
import com.dpiengine.inspect.AppClassifier;
import com.dpiengine.inspect.AppType;
import com.dpiengine.packet.PacketParser;
import com.dpiengine.rules.RuleDecision;
import com.dpiengine.rules.RuleManager;
import com.dpiengine.rules.RuleSet;
import java.io.IOException;
import java.nio.file.Path;
import java.util.Arrays;

/** Read-back verifier runnable from target/test-classes; all comparisons use PcapReader. */
public final class PcapOutputVerifier {
    public record Counts(long input, long written, long blocked) { }
    public static Counts verify(Path input, Path output, RuleSet rules) throws IOException {
        long count = 0, written = 0, blocked = 0;
        PacketParser parser = new PacketParser();
        AppClassifier classifier = new AppClassifier();
        FlowTracker tracker = new FlowTracker();
        RuleManager manager = new RuleManager(rules);
        try (PcapReader source = new PcapReader(input); PcapReader result = new PcapReader(output)) {
            if (!source.globalHeader().equals(result.globalHeader())) throw new IOException("Global header changed");
            var next = source.readPacket();
            while (next.isPresent()) {
                CapturedPacket expected = next.orElseThrow();
                count++;
                boolean allow = true;
                var parsed = source.globalHeader().network() == 1 ? parser.parse(expected)
                        : java.util.Optional.<com.dpiengine.packet.ParsedPacket>empty();
                if (parsed.isPresent()) {
                    var packet = parsed.orElseThrow();
                    var inspection = classifier.inspect(expected, packet);
                    var flow = tracker.track(expected, packet, inspection);
                    allow = manager.evaluate(packet, inspection, flow).decision() == RuleDecision.ALLOW;
                }
                if (allow) {
                    CapturedPacket actual = result.readPacket().orElseThrow(() -> new IOException("Missing allowed packet"));
                    if (!expected.timestamp().equals(actual.timestamp())
                            || expected.capturedLength() != actual.capturedLength()
                            || expected.originalLength() != actual.originalLength()
                            || !Arrays.equals(expected.rawBytes(), actual.rawBytes())) {
                        throw new IOException("Packet contents/order changed at input packet " + count);
                    }
                    written++;
                } else blocked++;
                next = source.readPacket();
            }
            if (result.readPacket().isPresent()) throw new IOException("Unexpected extra packet");
        }
        return new Counts(count, written, blocked);
    }

    public static void main(String[] args) throws IOException {
        RuleSet rules = args.length > 2 && args[2].equals("--demo-rules")
                ? RuleSet.builder().blockApplication(AppType.YOUTUBE).blockDomain("facebook.com").blockIpv4("192.168.1.50").build()
                : RuleSet.empty();
        Counts counts = verify(Path.of(args[0]), Path.of(args[1]), rules);
        System.out.println("Verified " + Path.of(args[1]).toAbsolutePath().normalize() + ": " + counts
                + "; header, timestamps, lengths, raw bytes, and order match");
    }
}
