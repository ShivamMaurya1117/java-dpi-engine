package com.dpiengine.rules;

import com.dpiengine.flow.FlowKey;
import com.dpiengine.flow.FlowState;
import com.dpiengine.inspect.InspectionResult;
import com.dpiengine.packet.ParsedPacket;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/** Single-threaded manager. Only BLOCK is cached, so later classification can block an allowed flow. */
public final class RuleManager {
    private RuleSet rules;
    private final HashMap<FlowKey, RuleEvaluation> blockedFlows = new HashMap<>();
    public RuleManager() { this(RuleSet.empty()); }
    public RuleManager(RuleSet rules) { this.rules = Objects.requireNonNull(rules); }
    public RuleSet rules() { return rules; }

    /** New configuration affects unblocked flows; existing blocks stay sticky until explicitly cleared. */
    public void setRules(RuleSet rules) { this.rules = Objects.requireNonNull(rules); }
    public void clearFlowDecisions() { blockedFlows.clear(); }
    public Map<FlowKey, RuleEvaluation> blockedFlows() { return Map.copyOf(blockedFlows); }

    public RuleEvaluation evaluate(ParsedPacket packet, InspectionResult inspection, FlowState flow) {
        FlowKey key = key(packet);
        if (key != null && blockedFlows.containsKey(key)) return blockedFlows.get(key);
        RuleEvaluation evaluation = rules.evaluate(packet, inspection, flow);
        if (key != null && evaluation.decision() == RuleDecision.BLOCK) blockedFlows.put(key, evaluation);
        return evaluation;
    }

    private static FlowKey key(ParsedPacket packet) {
        if (packet == null || Ipv4Addresses.normalize(packet.sourceIp()).isEmpty()
                || Ipv4Addresses.normalize(packet.destinationIp()).isEmpty()) return null;
        try {
            return FlowKey.from(packet);
        } catch (IllegalArgumentException | NullPointerException e) {
            return null;
        }
    }
}
