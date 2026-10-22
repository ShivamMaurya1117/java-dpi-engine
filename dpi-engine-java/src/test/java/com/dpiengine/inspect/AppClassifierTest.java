package com.dpiengine.inspect;

import com.dpiengine.flow.FlowTracker;
import com.dpiengine.flow.FlowState;
import com.dpiengine.packet.PacketParser;
import com.dpiengine.packet.ParsedPacket;
import com.dpiengine.pcap.CapturedPacket;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import java.nio.ByteBuffer;
import java.util.Map;
import static org.junit.jupiter.api.Assertions.*;
import static com.dpiengine.inspect.InspectionFixtures.*;

class AppClassifierTest {
    private final AppClassifier classifier = new AppClassifier();
    private final PacketParser parser = new PacketParser();

    private ParsedPacket parsed(CapturedPacket capture) { return parser.parse(capture).orElseThrow(); }
    private InspectionResult inspect(CapturedPacket capture) { return classifier.inspect(capture, parsed(capture)); }
    private FlowState track(FlowTracker tracker, byte[] payload, int protocol, int port) {
        CapturedPacket captured = frame(payload, protocol, 60000, port, false);
        return tracker.track(captured, parsed(captured));
    }

    @ParameterizedTest
    @CsvSource({
            "google.com,GOOGLE", "gstatic.com,GOOGLE", "googleapis.com,GOOGLE", "ggpht.com,GOOGLE", "gvt1.com,GOOGLE",
            "youtube.com,YOUTUBE", "ytimg.com,YOUTUBE", "youtu.be,YOUTUBE",
            "facebook.com,FACEBOOK", "fbcdn.net,FACEBOOK", "fb.com,FACEBOOK", "fbsbx.com,FACEBOOK", "meta.com,FACEBOOK",
            "instagram.com,INSTAGRAM", "cdninstagram.com,INSTAGRAM", "whatsapp.com,WHATSAPP", "whatsapp.net,WHATSAPP", "wa.me,WHATSAPP",
            "twitter.com,TWITTER", "twimg.com,TWITTER", "x.com,TWITTER", "t.co,TWITTER",
            "netflix.com,NETFLIX", "netflix.net,NETFLIX", "nflxvideo.net,NETFLIX", "nflximg.net,NETFLIX", "nflximg.com,NETFLIX",
            "amazon.com,AMAZON", "amazonaws.com,AMAZON", "cloudfront.net,AMAZON", "aws.com,AMAZON",
            "microsoft.com,MICROSOFT", "msn.com,MICROSOFT", "office.com,MICROSOFT", "office365.com,MICROSOFT", "azure.com,MICROSOFT",
            "live.com,MICROSOFT", "outlook.com,MICROSOFT", "bing.com,MICROSOFT",
            "apple.com,APPLE", "icloud.com,APPLE", "mzstatic.com,APPLE", "itunes.com,APPLE",
            "telegram.org,TELEGRAM", "t.me,TELEGRAM", "tiktok.com,TIKTOK", "tiktokcdn.com,TIKTOK",
            "musical.ly,TIKTOK", "bytedance.com,TIKTOK", "spotify.com,SPOTIFY", "scdn.co,SPOTIFY",
            "zoom.us,ZOOM", "zoom.com,ZOOM", "discord.com,DISCORD", "discordapp.com,DISCORD", "github.com,GITHUB",
            "githubusercontent.com,GITHUB", "cloudflare.com,CLOUDFLARE"})
    void matchesExactDomainsAndValidSubdomainsOnly(String domain, AppType expected) {
        assertEquals(expected, classifier.classifyDomain(domain, AppType.UNKNOWN));
        assertEquals(expected, classifier.classifyDomain("www." + domain, AppType.UNKNOWN));
        assertEquals(expected, classifier.classifyDomain("a.b." + domain, AppType.UNKNOWN));
        assertEquals(expected, classifier.classifyDomain(domain.toUpperCase(java.util.Locale.ROOT) + ".", AppType.UNKNOWN));
        assertEquals(expected, classifier.classifyDomain("WWW." + domain.toUpperCase(java.util.Locale.ROOT) + ".", AppType.UNKNOWN));
        assertEquals(AppType.UNKNOWN, classifier.classifyDomain("not" + domain, AppType.UNKNOWN));
        assertEquals(AppType.UNKNOWN, classifier.classifyDomain(domain + ".evil.example", AppType.UNKNOWN));
        assertEquals(AppType.UNKNOWN, classifier.classifyDomain("evil-" + domain, AppType.UNKNOWN));
        assertEquals(AppType.UNKNOWN, classifier.classifyDomain(domain + "evil", AppType.UNKNOWN));
    }

    @ParameterizedTest
    @CsvSource({"www.microsoft.com,MICROSOFT", "www.netflix.com,NETFLIX",
            "login.microsoft.com,MICROSOFT", "api.netflix.com,NETFLIX", "www.youtube.com,YOUTUBE"})
    void fixesCollisionsThroughTlsAndFlowClassification(String domain, AppType expected) {
        assertEquals(new InspectionResult(expected, domain), inspect(frame(tls(domain), 6, 60000, 443, false)));
        FlowTracker tracker = new FlowTracker();
        track(tracker, new byte[0], 6, 443);
        FlowState flow = track(tracker, tls(domain), 6, 443);
        assertEquals(expected, flow.appType());
        assertEquals(domain, flow.hostname());
        assertEquals(Map.of(expected, 1L), tracker.applicationDistribution());
    }

    @ParameterizedTest
    @ValueSource(strings = {"notyoutube.com", "youtube.com.evil.example", "youtube.example", "fakegoogle.com",
            "google.com.evil.example", "cloudflare-attacker.example", "cf-attacker.example",
            "microsoft.evil.example", "netflix.evil.example", "t.co.evil.example", "not.co",
            "notx.com", "twitter.com.evil.example", "google", "youtube", "netflix", "cf-"})
    void misleadingNamesRetainTheirProtocolFallback(String domain) {
        assertEquals(AppType.UNKNOWN, classifier.classifyDomain(domain, AppType.UNKNOWN));
        assertEquals(AppType.HTTP, classifier.classifyDomain(domain, AppType.HTTP));
        assertEquals(AppType.HTTPS, classifier.classifyDomain(domain, AppType.HTTPS));
        assertEquals(AppType.DNS, classifier.classifyDomain(domain, AppType.DNS));
    }

    @ParameterizedTest
    @ValueSource(strings = {"", " youtube.com", "youtube.com ", "youtube.com..", ".youtube.com",
            "bad..youtube.com", "-bad.youtube.com", "bad_.youtube.com", "youtube.com:443",
            "https://youtube.com", "youtube.com/", "youtube.com\u0000", "youtub\u00e9.com"})
    void malformedDomainNamesUseFallback(String domain) {
        assertEquals(AppType.HTTPS, classifier.classifyDomain(domain, AppType.HTTPS));
    }

    @Test
    void nullHostnameUsesFallback() {
        assertEquals(AppType.UNKNOWN, classifier.classifyDomain(null, AppType.UNKNOWN));
    }

    @Test
    void googleImageSubdomainsRemainGoogle() {
        assertEquals(AppType.GOOGLE, classifier.classifyDomain("yt3.ggpht.com", AppType.UNKNOWN));
        assertEquals(AppType.GOOGLE, classifier.classifyDomain("notyt3.ggpht.com", AppType.UNKNOWN));
        assertEquals(AppType.UNKNOWN, classifier.classifyDomain("yt3.ggpht.com.evil.example", AppType.UNKNOWN));
    }

    @Test
    void genericClassificationUsesProtocolContext() {
        assertEquals(AppType.HTTP, inspect(frame(http("example.org"), 6, 60000, 80, false)).appType());
        assertEquals(AppType.HTTPS, inspect(frame(tls("example.org"), 6, 60000, 443, false)).appType());
        assertEquals(AppType.DNS, inspect(frame(dns("example.org"), 17, 60000, 53, false)).appType());
        assertEquals(AppType.UNKNOWN, inspect(frame(new byte[]{1, 2}, 17, 60000, 443, false)).appType());
        assertEquals(AppType.UNKNOWN, classifier.classifyDomain("openai.com", AppType.UNKNOWN));
        assertEquals(AppType.HTTP, inspect(frame(new byte[0], 6, 80, 60000, true)).appType());
        assertEquals(AppType.HTTPS, inspect(frame(new byte[0], 6, 443, 60000, true)).appType());
    }

    @Test
    void extractionUsesParsedOffsetsAndExcludesEthernetPadding() {
        CapturedPacket capture = frame(tls("www.google.com"), 6, 60000, 443, false);
        assertEquals(62, parsed(capture).payloadOffset());
        assertEquals(new InspectionResult(AppType.GOOGLE, "www.google.com"), inspect(capture));
        byte[] request = http("github.com");
        capture = frame(java.util.Arrays.copyOf(request, request.length - 4), 6, 60000, 80, false);
        byte[] raw = capture.rawBytes();
        ParsedPacket packet = parsed(capture);
        System.arraycopy(new byte[]{13, 10, 13, 10}, 0, raw, packet.payloadOffset() + packet.payloadLength(), 4);
        CapturedPacket padded = new CapturedPacket(capture.timestamp(), raw.length, raw.length, raw);
        assertEquals(new InspectionResult(AppType.HTTP, ""), classifier.inspect(padded, packet));
    }

    @Test
    void detectsCompleteTcpDnsMessageButNotPartialMessage() {
        byte[] query = dns("github.com");
        byte[] payload = ByteBuffer.allocate(query.length + 2).putShort((short) query.length).put(query).array();
        assertEquals(new InspectionResult(AppType.GITHUB, "github.com"), inspect(frame(payload, 6, 60000, 53, false)));
        payload[1]++;
        assertEquals(new InspectionResult(AppType.DNS, ""), inspect(frame(payload, 6, 60000, 53, false)));
    }

    @ParameterizedTest
    @CsvSource({"6,443,HTTPS", "6,80,HTTP", "17,53,DNS", "6,9000,UNKNOWN"})
    void malformedPayloadKeepsGenericClassification(int protocol, int port, AppType expected) {
        assertEquals(new InspectionResult(expected, ""), inspect(frame(new byte[]{22, 3, 1, -1}, protocol, 60000, port, false)));
    }

    @Test
    void httpsFlowUpgradesWithoutLosingStatisticsOrDowngrading() {
        FlowTracker tracker = new FlowTracker();
        FlowState first = track(tracker, new byte[0], 6, 443);
        assertEquals(AppType.HTTPS, first.appType());
        assertEquals(Map.of(AppType.HTTPS, 1L), tracker.applicationDistribution());
        FlowState upgraded = track(tracker, tls("www.google.com"), 6, 443);
        assertEquals(AppType.GOOGLE, upgraded.appType());
        assertEquals("www.google.com", upgraded.hostname());
        assertEquals(2, upgraded.packetCount());
        assertTrue(upgraded.totalCapturedBytes() > first.totalCapturedBytes());
        assertEquals(Map.of(AppType.GOOGLE, 1L), tracker.applicationDistribution());
        FlowState finalState = track(tracker, tls("github.com"), 6, 443);
        assertEquals(AppType.GOOGLE, finalState.appType());
        assertEquals("www.google.com", finalState.hostname());
        assertEquals(3, finalState.packetCount());
        assertEquals(AppType.HTTPS, first.appType()); // Immutable snapshot.
    }

    @Test
    void genericHostnameDoesNotPreventLaterSpecificUpgrade() {
        FlowTracker tracker = new FlowTracker();
        assertEquals(AppType.HTTPS, track(tracker, tls("example.org"), 6, 443).appType());
        FlowState upgraded = track(tracker, tls("youtube.com"), 6, 443);
        assertEquals(AppType.YOUTUBE, upgraded.appType());
        assertEquals("youtube.com", upgraded.hostname());
        assertEquals(AppType.YOUTUBE, track(tracker, new byte[0], 6, 443).appType());
    }

    @Test
    void httpDnsAndUnknownCanUpgrade() {
        FlowTracker tracker = new FlowTracker();
        track(tracker, new byte[0], 6, 80);
        assertEquals(AppType.GITHUB, track(tracker, http("github.com"), 6, 80).appType());
        track(tracker, new byte[0], 17, 53);
        assertEquals(AppType.GOOGLE, track(tracker, dns("google.com"), 17, 53).appType());
        track(tracker, new byte[0], 6, 9000);
        assertEquals(AppType.HTTP, track(tracker, http("example.org"), 6, 9000).appType());
        assertEquals(AppType.GITHUB, track(tracker, http("github.com"), 6, 9000).appType());
        assertEquals(3, tracker.uniqueFlowCount());
    }

    @Test
    void reverseFlowDoesNotInheritClassification() {
        FlowTracker tracker = new FlowTracker();
        track(tracker, tls("google.com"), 6, 443);
        CapturedPacket reverse = frame(new byte[0], 6, 443, 60000, true);
        FlowState state = tracker.track(reverse, parsed(reverse));
        assertEquals(AppType.HTTPS, state.appType());
        assertEquals("", state.hostname());
        assertEquals(2, tracker.uniqueFlowCount());
        assertEquals(Map.of(AppType.GOOGLE, 1L, AppType.HTTPS, 1L), tracker.applicationDistribution());
        assertThrows(UnsupportedOperationException.class, () -> tracker.applicationDistribution().clear());
    }
}
