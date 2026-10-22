package com.dpiengine.rules;

import com.dpiengine.flow.FlowKey;
import com.dpiengine.flow.FlowState;
import com.dpiengine.flow.FlowStatus;
import com.dpiengine.inspect.AppType;
import com.dpiengine.inspect.InspectionResult;
import com.dpiengine.packet.ParsedPacket;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import java.time.Instant;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import static org.junit.jupiter.api.Assertions.*;

class RuleManagerTest {
    private ParsedPacket packet(String source, String destination, int sourcePort, int destinationPort) {
        return new ParsedPacket(Instant.EPOCH, "aa:bb:cc:dd:ee:ff", "00:01:02:03:04:05", 0x0800,
                source, destination, 6, 64, sourcePort, destinationPort, 0, 0, 0, 20, 34, 20, 54, 0);
    }
    private ParsedPacket packet() { return packet("192.168.1.2", "8.8.8.8", 60000, 443); }
    private ParsedPacket reverse() { return packet("8.8.8.8", "192.168.1.2", 443, 60000); }
    private InspectionResult inspection(AppType app, String hostname) { return new InspectionResult(app, hostname); }
    private FlowState flow(ParsedPacket packet, AppType app, String hostname) {
        return new FlowState(FlowKey.from(packet), 2, 108, Instant.EPOCH, Instant.EPOCH,
                FlowStatus.ACTIVE, app, hostname);
    }
    private RuleEvaluation evaluate(RuleSet rules, AppType app, String hostname) {
        return rules.evaluate(packet(), inspection(app, hostname), null);
    }

    @Test
    void defaultAllowsWithoutClassification() {
        RuleManager manager = new RuleManager();
        assertEquals(RuleEvaluation.allow(), manager.evaluate(packet(), null, null));
        assertEquals(RuleEvaluation.allow(), manager.evaluate(packet(), inspection(AppType.UNKNOWN, ""), null));
        assertTrue(manager.blockedFlows().isEmpty());
    }

    @ParameterizedTest
    @ValueSource(strings = {"YOUTUBE", "MICROSOFT", "NETFLIX", "HTTPS", "DNS", "UNKNOWN"})
    void explicitApplicationRulesBlockOnlyThatApplication(AppType app) {
        RuleSet rules = RuleSet.builder().blockApplication(app).build();
        assertEquals(new RuleEvaluation(RuleDecision.BLOCK,
                List.of(new BlockReason(BlockReason.Type.APPLICATION, app.name()))), evaluate(rules, app, ""));
        AppType other = app == AppType.UNKNOWN ? AppType.HTTP : AppType.UNKNOWN;
        assertEquals(RuleDecision.ALLOW, evaluate(rules, other, "").decision());
    }

    @ParameterizedTest
    @CsvSource({"youtube.com,BLOCK", "www.youtube.com,BLOCK", "a.b.youtube.com,BLOCK",
            "WWW.YouTube.COM.,BLOCK", "notyoutube.com,ALLOW", "youtube.com.evil.example,ALLOW",
            "evil-youtube.com,ALLOW", "youtube.example,ALLOW", "youtube.comevil,ALLOW"})
    void domainsMatchAtBoundaries(String host, RuleDecision expected) {
        RuleSet rules = RuleSet.builder().blockDomain("YouTube.COM.").build();
        assertEquals(expected, evaluate(rules, AppType.UNKNOWN, host).decision());
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "youtube.com:443", "youtube.com..", "bad..youtube.com", " youtube.com",
            "https://youtube.com", "bad_.youtube.com", "youtube.com\u0000"})
    void invalidOrMissingHostnamesDoNotMatchDomainRules(String host) {
        assertEquals(RuleDecision.ALLOW,
                evaluate(RuleSet.builder().blockDomain("youtube.com").build(), AppType.UNKNOWN, host).decision());
    }

    @Test
    void exactIpv4MatchesEitherEndpointAndNotSimilarAddresses() {
        RuleSet rules = RuleSet.builder().blockIpv4("192.168.1.2").build();
        assertEquals(RuleDecision.BLOCK, rules.evaluate(packet(), null, null).decision());
        assertEquals(RuleDecision.BLOCK, rules.evaluate(reverse(), null, null).decision());
        assertEquals(RuleDecision.ALLOW,
                rules.evaluate(packet("192.168.1.20", "8.8.8.8", 60000, 443), null, null).decision());
        assertEquals(RuleDecision.ALLOW,
                rules.evaluate(packet("invalid", "192.168.1.256", 60000, 443), null, null).decision());
    }

    @ParameterizedTest
    @ValueSource(strings = {"192.168.1.256", "192.168.1", "192.168.01.2", "192.168.1.2/24", "localhost",
            "192.168.1.*", "-1.0.0.0", " 192.168.1.2", "::1", ""})
    void rejectsInvalidIpv4Configuration(String address) {
        assertThrows(IllegalArgumentException.class, () -> RuleSet.builder().blockIpv4(address).build());
    }

    @ParameterizedTest
    @ValueSource(strings = {"*.youtube.com", "youtube.com:443", "https://youtube.com", "", "bad..org"})
    void rejectsInvalidDomainConfiguration(String domain) {
        assertThrows(IllegalArgumentException.class, () -> RuleSet.builder().blockDomain(domain).build());
    }

    @Test
    void anyMatchingRuleBlocksAndAllReasonsAreReturned() {
        RuleSet rules = RuleSet.builder().blockApplication(AppType.YOUTUBE).blockDomain("youtube.com")
                .blockIpv4("192.168.1.2").build();
        RuleEvaluation result = evaluate(rules, AppType.YOUTUBE, "www.youtube.com");
        assertEquals(RuleDecision.BLOCK, result.decision());
        assertEquals(List.of(new BlockReason(BlockReason.Type.IPV4, "192.168.1.2"),
                new BlockReason(BlockReason.Type.APPLICATION, "YOUTUBE"),
                new BlockReason(BlockReason.Type.DOMAIN, "youtube.com")), result.reasons());
        assertEquals(RuleDecision.BLOCK, evaluate(rules, AppType.UNKNOWN, "").decision());
        assertEquals(RuleDecision.BLOCK,
                evaluate(RuleSet.builder().blockDomain("youtube.com").blockApplication(AppType.NETFLIX).build(),
                        AppType.UNKNOWN, "youtube.com").decision());
    }

    @Test
    void firstBlockPersistsEvenWithoutHostnameOrClassification() {
        RuleManager manager = new RuleManager(RuleSet.builder().blockDomain("youtube.com").build());
        RuleEvaluation first = manager.evaluate(packet(), inspection(AppType.YOUTUBE, "youtube.com"), null);
        assertEquals(first, manager.evaluate(packet(), inspection(AppType.UNKNOWN, ""), null));
        assertEquals(1, manager.blockedFlows().size());
        assertEquals(first, manager.blockedFlows().get(FlowKey.from(packet())));
        assertThrows(UnsupportedOperationException.class, () -> manager.blockedFlows().clear());
    }

    @Test
    void allowedFlowCanBecomeBlockedLater() {
        RuleManager manager = new RuleManager(RuleSet.builder().blockApplication(AppType.YOUTUBE).build());
        assertEquals(RuleDecision.ALLOW, manager.evaluate(packet(), inspection(AppType.HTTPS, ""), null).decision());
        assertTrue(manager.blockedFlows().isEmpty());
        assertEquals(RuleDecision.BLOCK,
                manager.evaluate(packet(), inspection(AppType.YOUTUBE, "youtube.com"), null).decision());
        assertEquals(RuleDecision.BLOCK, manager.evaluate(packet(), null, null).decision());
    }

    @Test
    void reverseTrafficAndDifferentPortsRemainIndependent() {
        RuleManager manager = new RuleManager(RuleSet.builder().blockApplication(AppType.YOUTUBE).build());
        manager.evaluate(packet(), inspection(AppType.YOUTUBE, "youtube.com"), null);
        assertEquals(RuleDecision.ALLOW, manager.evaluate(reverse(), inspection(AppType.HTTPS, ""), null).decision());
        assertEquals(RuleDecision.ALLOW,
                manager.evaluate(packet("192.168.1.2", "8.8.8.8", 60001, 443), null, null).decision());
        assertEquals(RuleDecision.BLOCK,
                manager.evaluate(reverse(), inspection(AppType.YOUTUBE, "youtube.com"), null).decision());
        assertEquals(2, manager.blockedFlows().size());
    }

    @Test
    void usesRetainedFlowClassificationAndHostWithoutBlockingUnknownByMistake() {
        FlowState flow = flow(packet(), AppType.YOUTUBE, "youtube.com");
        assertEquals(RuleDecision.BLOCK, RuleSet.builder().blockApplication(AppType.YOUTUBE).build()
                .evaluate(packet(), inspection(AppType.UNKNOWN, ""), flow).decision());
        assertEquals(RuleDecision.BLOCK, RuleSet.builder().blockDomain("youtube.com").build()
                .evaluate(packet(), null, flow).decision());
        assertEquals(RuleDecision.ALLOW, RuleSet.builder().blockApplication(AppType.UNKNOWN).build()
                .evaluate(packet(), inspection(AppType.UNKNOWN, ""), flow).decision());
    }

    @Test
    void currentHostnameCanMatchDespiteDifferentRetainedSpecificApplication() {
        assertEquals(RuleDecision.BLOCK, RuleSet.builder().blockDomain("youtube.com").build()
                .evaluate(packet(), inspection(AppType.YOUTUBE, "youtube.com"),
                        flow(packet(), AppType.GOOGLE, "google.com")).decision());
    }

    @Test
    void unrelatedFlowSnapshotCannotBlockReverseTraffic() {
        RuleSet rules = RuleSet.builder().blockApplication(AppType.YOUTUBE).blockDomain("youtube.com").build();
        assertEquals(RuleDecision.ALLOW,
                rules.evaluate(reverse(), null, flow(packet(), AppType.YOUTUBE, "youtube.com")).decision());
    }

    @Test
    void updatesConfigurationButRequiresExplicitResetToReleaseStickyBlocks() {
        RuleManager manager = new RuleManager();
        assertEquals(RuleDecision.ALLOW, manager.evaluate(packet(), null, null).decision());
        manager.setRules(RuleSet.builder().blockIpv4("192.168.1.2").build());
        assertEquals(RuleDecision.BLOCK, manager.evaluate(packet(), null, null).decision());
        manager.setRules(RuleSet.empty());
        assertEquals(RuleDecision.BLOCK, manager.evaluate(packet(), null, null).decision());
        manager.clearFlowDecisions();
        assertEquals(RuleDecision.ALLOW, manager.evaluate(packet(), null, null).decision());
    }

    @Test
    void ruleConfigurationAndReasonsAreImmutableAndDeduplicated() {
        Set<String> domains = new HashSet<>(Set.of("YouTube.com", "youtube.com."));
        RuleSet rules = new RuleSet(Set.of(), domains, Set.of());
        domains.clear();
        assertEquals(Set.of("youtube.com"), rules.domains());
        assertThrows(UnsupportedOperationException.class, () -> rules.domains().clear());
        RuleSet.Builder builder = RuleSet.builder().blockDomain("youtube.com");
        RuleSet snapshot = builder.build();
        builder.blockDomain("netflix.com");
        assertEquals(1, snapshot.domains().size());
        RuleEvaluation result = evaluate(rules, AppType.UNKNOWN, "youtube.com");
        assertEquals(1, result.reasons().size());
        assertThrows(UnsupportedOperationException.class, () -> result.reasons().clear());
        assertThrows(IllegalArgumentException.class, () -> new RuleEvaluation(RuleDecision.BLOCK, List.of()));
    }

    @Test
    void nullPacketAndMalformedFlowKeysDoNotCrashOrPoisonCache() {
        RuleManager manager = new RuleManager(RuleSet.builder().blockDomain("youtube.com").build());
        assertEquals(RuleDecision.ALLOW, manager.evaluate(null, null, null).decision());
        ParsedPacket malformed = packet(null, "invalid", -1, 70000);
        assertEquals(RuleDecision.ALLOW, manager.evaluate(malformed, null, null).decision());
        assertEquals(RuleDecision.BLOCK,
                manager.evaluate(malformed, inspection(AppType.UNKNOWN, "youtube.com"), null).decision());
        assertTrue(manager.blockedFlows().isEmpty());
    }
}
