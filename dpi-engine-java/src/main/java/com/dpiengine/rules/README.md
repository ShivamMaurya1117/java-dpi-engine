RuleSet is an immutable configuration with stateless evaluation. Use its builder
to configure applications, domain roots, and exact dotted-decimal IPv4 addresses.
Domains use shared hostname validation, case normalization, trailing-dot removal,
and exact or dot-delimited subdomain matching. IPv4 rules check either endpoint;
CIDR, wildcards, leading-zero octets, and hostname lookups are unsupported. Invalid
configuration is rejected rather than silently installing an ineffective rule.

RuleEvaluation contains ALLOW with no reasons, or BLOCK with all matching rule
reasons in deterministic order. UNKNOWN is allowed by default, but can be explicitly
blocked. Missing/invalid hostnames never match domain rules. Existing specific flow
classification takes precedence over generic packet classification; both the current
inspection hostname and the matching flow's retained hostname are checked. An
unrelated or reverse flow snapshot cannot supply classification to a packet.

RuleManager retains the first BLOCK evaluation by directional FlowKey. ALLOW is
never cached: a later hostname or application upgrade can block an initially
allowed flow. Reverse traffic is evaluated independently. Replacing the RuleSet
does not release existing blocks; clearFlowDecisions explicitly resets that cache.
No packets are retroactively blocked. Statistics and inspection continue after a
flow is blocked. This is an in-memory decision engine; it does not write PCAP files.

From dpi-engine-java, run:
  java -cp target/classes com.dpiengine.Main
  java -cp target/classes com.dpiengine.Main --demo-rules
  java -cp target/classes com.dpiengine.Main ../test_dpi.pcap --block-app DNS --block-domain example.org --block-ip 203.0.113.99

No rules are enabled by default. The legacy --demo-rules flag still uses YOUTUBE, facebook.com and 192.168.1.50. For the current fixture use the explicit DNS/example.org/203.0.113.99 flags above; the legacy flag does not match it.
Allowed/blocked counts cover all input packets. Unsupported packets remain in the
separate skipped count and are allowed unchanged. Reason counts include persisted reasons on later blocked
packets, and may overlap when a packet has multiple matching rules.

Add --output PATH to write allowed packets in input order, preserving all PCAP
header properties, timestamps, lengths, and bytes. Without --output this remains
analysis only. Output must be a new file in an existing directory; existing files
and input aliases are rejected. If I/O or input truncation fails during writing,
the output may be incomplete and Main reports failure instead of success.
