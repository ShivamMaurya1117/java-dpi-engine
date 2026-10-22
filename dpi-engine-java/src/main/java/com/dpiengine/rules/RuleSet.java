package com.dpiengine.rules;

import com.dpiengine.flow.FlowKey;
import com.dpiengine.flow.FlowState;
import com.dpiengine.inspect.AppType;
import com.dpiengine.inspect.Hostnames;
import com.dpiengine.inspect.InspectionResult;
import com.dpiengine.packet.ParsedPacket;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/** Immutable rule configuration and stateless evaluation; any match blocks.
 * Domain roots include subdomains. IP rules apply to either endpoint, without CIDR or wildcards.
 */
public record RuleSet(Set<AppType> applications, Set<String> domains, Set<String> ipv4Addresses) {
    public RuleSet {
        applications = Set.copyOf(applications);
        Set<String> normalizedDomains = new HashSet<>();
        for (String domain : domains) normalizedDomains.add(Hostnames.normalize(domain)
                .orElseThrow(() -> new IllegalArgumentException("Invalid domain rule: " + domain)));
        domains = Set.copyOf(normalizedDomains);
        Set<String> normalizedIps = new HashSet<>();
        for (String address : ipv4Addresses) normalizedIps.add(Ipv4Addresses.normalize(address)
                .orElseThrow(() -> new IllegalArgumentException("Invalid IPv4 rule: " + address)));
        ipv4Addresses = Set.copyOf(normalizedIps);
    }

    public static RuleSet empty() { return new RuleSet(Set.of(), Set.of(), Set.of()); }
    public static Builder builder() { return new Builder(); }

    public RuleEvaluation evaluate(ParsedPacket packet, InspectionResult inspection, FlowState flow) {
        if (packet == null) return RuleEvaluation.allow();
        // A reverse or unrelated flow snapshot must never supply classification to this packet.
        if (flow != null && !sameFlow(packet, flow)) flow = null;
        List<BlockReason> reasons = new ArrayList<>();
        Set<String> endpoints = new HashSet<>();
        Ipv4Addresses.normalize(packet.sourceIp()).ifPresent(endpoints::add);
        Ipv4Addresses.normalize(packet.destinationIp()).ifPresent(endpoints::add);
        endpoints.stream().filter(ipv4Addresses::contains).sorted()
                .forEach(ip -> reasons.add(new BlockReason(BlockReason.Type.IPV4, ip)));

        AppType app = inspection == null ? AppType.UNKNOWN : inspection.appType();
        if (flow != null && (flow.appType().isSpecific() || app == AppType.UNKNOWN)) app = flow.appType();
        if (applications.contains(app)) reasons.add(new BlockReason(BlockReason.Type.APPLICATION, app.name()));

        Set<String> hostnames = new HashSet<>();
        if (inspection != null) Hostnames.normalize(inspection.hostname()).ifPresent(hostnames::add);
        if (flow != null) Hostnames.normalize(flow.hostname()).ifPresent(hostnames::add);
        domains.stream().sorted().filter(root -> hostnames.stream()
                .anyMatch(host -> host.equals(root) || host.endsWith("." + root)))
                .forEach(root -> reasons.add(new BlockReason(BlockReason.Type.DOMAIN, root)));
        return reasons.isEmpty() ? RuleEvaluation.allow() : new RuleEvaluation(RuleDecision.BLOCK, reasons);
    }

    private static boolean sameFlow(ParsedPacket packet, FlowState flow) {
        try {
            return FlowKey.from(packet).equals(flow.key());
        } catch (IllegalArgumentException | NullPointerException e) {
            return false;
        }
    }

    public static final class Builder {
        private final Set<AppType> apps = new HashSet<>();
        private final Set<String> domains = new HashSet<>();
        private final Set<String> ips = new HashSet<>();
        public Builder blockApplication(AppType app) { apps.add(Objects.requireNonNull(app)); return this; }
        public Builder blockDomain(String domain) { domains.add(Objects.requireNonNull(domain)); return this; }
        public Builder blockIpv4(String address) { ips.add(Objects.requireNonNull(address)); return this; }
        public RuleSet build() { return new RuleSet(apps, domains, ips); }
    }
}
