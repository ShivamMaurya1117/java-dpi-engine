package com.dpiengine.rules;

import java.util.List;
import java.util.Objects;

public record RuleEvaluation(RuleDecision decision, List<BlockReason> reasons) {
    public RuleEvaluation {
        Objects.requireNonNull(decision);
        reasons = List.copyOf(reasons);
        if ((decision == RuleDecision.BLOCK) != !reasons.isEmpty()) {
            throw new IllegalArgumentException("BLOCK requires reasons; ALLOW must have no reasons");
        }
    }
    public static RuleEvaluation allow() { return new RuleEvaluation(RuleDecision.ALLOW, List.of()); }
}
