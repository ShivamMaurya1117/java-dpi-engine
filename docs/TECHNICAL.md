# Technical implementation

[Overview](../README.md) · [Architecture](ARCHITECTURE.md) · [API contract](API.md)

This is an **offline PCAP analyzer/filter**. It does not intercept live traffic, decrypt HTTPS or use ML. Application names are derived from explicit domain mappings and protocol/port heuristics. This document describes the Java implementation. Reference attribution is recorded in [PROVENANCE.md](../PROVENANCE.md).

## Classic-PCAP I/O

[PcapReader](../dpi-engine-java/src/main/java/com/dpiengine/pcap/PcapReader.java) owns a buffered input stream. Its 24-byte global header recognizes the four classic-PCAP magic encodings: big/little endian with microsecond or nanosecond resolution. It requires version 2.4 and nonzero snapshot length. It retains timezone, significant figures, snapshot length and network/link type. PCAPNG magic is unsupported.

Each 16-byte record header carries unsigned 32-bit seconds, timestamp fraction, captured length and original length in the capture's byte order. Fraction must fit its resolution; captured length cannot exceed original length or snapshot length. The absolute captured-length ceiling is 64 MiB. A caller can supply a lower positive byte budget, checked before body allocation. An absolute-ceiling violation is a format error; a lower caller-budget violation is `PcapLimitException`. Complete zero-length records are valid.

An empty read at a record boundary is clean EOF. Partial headers/bodies throw `EOFException`. Bad metadata throws `PcapFormatException`, distinct from storage I/O, although all are IOException subclasses. A reader cannot continue after a read failure. Timestamps become `Instant`; no wall-clock timestamp is substituted.

[PcapWriter](../dpi-engine-java/src/main/java/com/dpiengine/pcap/PcapWriter.java) writes the retained global header and allowed records using the original byte order/resolution. It preserves record timestamps, captured/original lengths and bytes without editing checksums or payloads. CLI output must be new, have an existing parent directory and not alias the input; `CREATE_NEW` also prevents overwriting. Output is buffered, so successful writes are guaranteed complete only after successful close. Processing failure can leave partial CLI output; partial written counts may represent submitted records when flushing fails. API partial files are subject to workspace cleanup and are not returned as successful processing results.

## Ethernet, IPv4 and transport parsing

[PacketParser](../dpi-engine-java/src/main/java/com/dpiengine/packet/PacketParser.java) returns an Optional parsed packet and uses bounds checks at each offset/length. It accepts Ethernet II's 14-byte header only when EtherType is IPv4 (`0x0800`). It requires IPv4 version 4, valid IHL/total length and all IP-declared bytes to be captured. IPv4 options are accommodated by IHL. Reserved flag, more-fragments flag and nonzero fragment offsets are rejected; DF alone is accepted.

Only TCP (6) and UDP (17) are parsed. TCP requires a complete minimum header and valid data offset, retaining ports, sequence, acknowledgement and nine flags including NS. UDP requires its eight-byte header and a valid length within the IP packet; inspection stops at UDP's declared end. Bytes beyond declared protocol lengths are not inspected as payload. The parser exposes MAC/IP addresses, TTL, header lengths and bounded payload offset/length.

There is no checksum verification, VLAN decapsulation, IPv6, fragment reassembly or TCP reassembly. Unsupported/malformed network records return empty rather than failing the capture. The engine counts these as skipped and **allows them unchanged**, without evaluating even IP rules. Core processing skips all records when the global link type is not 1; API prevalidation instead rejects such a capture with 400.

## Directional flow state

[FlowKey](../dpi-engine-java/src/main/java/com/dpiengine/flow/FlowKey.java) is a record of `(sourceIp, destinationIp, sourcePort, destinationPort, protocol)`. Record equality/hash include all five fields. There is no endpoint sorting, bidirectional canonicalization, DNS lookup or NAT correlation. Reversing endpoints normally creates another key.

[FlowTracker](../dpi-engine-java/src/main/java/com/dpiengine/flow/FlowTracker.java) keeps one entry per distinct parsed key for the run, with no idle eviction or key reset after connection closure. Reuse of a tuple in a capture therefore contributes to the same entry. Captured-byte counts include link/transport headers, not just payload. First/last timestamps are the minimum/maximum capture times even if records arrive out of timestamp order.

A first observation is NEW unless TCP FIN/RST marks it CLOSED. Subsequent observations become ACTIVE unless CLOSED was already seen; closure is sticky, and later packets still contribute. This is an observation status, not a complete TCP connection state machine. A first specific application and its hostname are retained; generic classification remains eligible for later upgrades. Reverse packets do not inherit forward classification. Final distribution counts each flow once, including flows whose packets were blocked.

## Packet-local inspection and application mapping

[AppClassifier](../dpi-engine-java/src/main/java/com/dpiengine/inspect/AppClassifier.java) begins with fallbacks based on either endpoint: TCP/UDP port 53 gives DNS, TCP 443 gives HTTPS, TCP 80 gives HTTP, otherwise UNKNOWN. UDP 443 alone does not imply HTTPS or QUIC.

For DNS context it uses `DnsQueryExtractor`, stripping the two-byte length prefix for TCP only when the complete indicated message is present in the packet. For other TCP payloads it tries TLS SNI first, then HTTP Host. A successful extraction establishes HTTPS or HTTP context even on a nonstandard port. The normalized hostname is then mapped to a specific application using an ordered table of explicit domain roots. Matching is exact or dot-delimited suffix: `www.youtube.com` matches `youtube.com`, whereas `notyoutube.com` does not. Unknown roots retain the protocol-context fallback. Mappings are fixed in Java code, not loaded from a service or trained model.

| Extractor | Accepted input and limitations |
| --- | --- |
| HTTP Host | Complete ASCII HTTP/1.0 or HTTP/1.1 request headers within 65536 bytes; methods GET/POST/PUT/HEAD/DELETE/PATCH/OPTIONS; single valid Host with optional numeric port 1–65535; no body scanning or response-host extraction |
| TLS SNI | Complete ClientHello inside one TLS handshake record in one packet; validates nested lengths and SNI structure; no split records/handshakes, decryption or encrypted-SNI support |
| DNS query | Standard query opcode, at least one question; validates all questions, returns first name; compressed question names and response packets are unsupported; no DNS answer-to-IP correlation |

`Hostnames.normalize` accepts ASCII alphanumeric/hyphen labels, with label length at most 63 and total length at most 253, lowercases them and removes a trailing root dot. It rejects empty labels and invalid characters; it does not trim whitespace or convert Unicode hostnames to IDNA. Extractors safely return empty for incomplete/malformed payloads, preserving generic fallback where possible. This is limited visibility, not proof that traffic is benign or correctly identified. `TLS` and `QUIC` enum values are reserved and not emitted.

## Rule evaluation and decision order

[RuleSet](../dpi-engine-java/src/main/java/com/dpiengine/rules/RuleSet.java) is immutable; duplicate normalized rules collapse into sets. IPv4 rules require exact dotted decimal, reject leading zeros/CIDR/wildcards and match either endpoint. Domain rules use the same hostname normalization and exact/subdomain matching. Application rules use AppType enum values, including UNKNOWN when explicitly requested.

Evaluation proceeds as follows:

1. A null parsed packet is allowed. An unrelated/reverse flow snapshot is discarded.
2. All matching endpoint-IP reasons are collected in sorted IP order.
3. Application starts from current inspection (UNKNOWN if absent). A matching retained flow supplies its app when specific, or when current inspection is UNKNOWN. A configured match adds one application reason.
4. Both the current inspection hostname and retained flow hostname are checked against sorted domain roots; each matching configured root adds a reason.
5. Any reason yields BLOCK; no reasons yields ALLOW. These categories combine rather than override each other.

[RuleManager](../dpi-engine-java/src/main/java/com/dpiengine/rules/RuleManager.java) first checks its directional block cache. A cached first BLOCK returns immediately with those retained reasons. ALLOW is never cached, so later inspection can block an initially allowed flow. No previously written packet is removed. Inspection and tracking continue for blocked flows. Reason packet counts include retained reasons on later packets and may overlap; their sum need not equal blockedPackets. Changing a RuleManager's RuleSet does not clear existing blocks; its explicit clear method does. Normal engine calls create fresh managers and do not share decisions across requests.

## Parallelism, ordering and executor lifecycle

`DpiEngineConfig` accepts 1–64 threads and a queue/window capacity of 1–4096 (default 64). One thread uses `DpiEngine` directly; 2–64 use [ParallelDpiEngine](../dpi-engine-java/src/main/java/com/dpiengine/engine/ParallelDpiEngine.java).

The coordinator reads/parses each record, globally admits directional keys against flow limits and assigns sequence numbers. Worker selection is `floorMod(hash ^ (hash >>> 16), workers)` using the full FlowKey hash. Unsupported records use sequence modulo worker count. Each worker has a single-thread executor, bounded FIFO queue, private tracker, classifier and rule manager. Thus packets in the same directional flow are processed in capture order without shared mutable flow state.

The global pending deque includes queued, running and finished-but-unconsumed futures. At capacity the coordinator consumes the oldest future before reading further. Only the coordinator updates packet decision counts and writes records, in sequence order. It polls futures with 100 ms waits to check other workers' failures; this is not a request deadline. Successful results merge worker state after termination, preserving sequential counts/output except elapsed time. CLI top-flow ties sort by printed key; API reason entries sort by reason string. JSON map iteration order is not a contract.

Normal EOF drains work and joins executors; truncated input drains complete submitted records before reporting the input error. Processing/write failure cancels/interrupts pending work. Shutdown first waits under one shared 30-second deadline, then calls forced shutdown and waits under a second shared 30-second deadline. Caller interrupt status is restored. Secondary shutdown errors are suppressed onto the primary failure. A worker ignoring interruption may survive the failed call; Java provides no safe forced thread kill. Failure statistics may include dispatched/classified packets ahead of the last output record and are not a complete successful report.

## Resource limits and API errors

[ProcessingLimits](../dpi-engine-java/src/main/java/com/dpiengine/engine/ProcessingLimits.java) bounds complete records, distinct parsed flows and captured bytes per record. Existing standalone constructors use unrestricted record/flow counts and the reader's 64 MiB ceiling. CLI has no flags exposing API workload budgets.

The API explicitly supplies 100000 records, 10000 flows, 262144 bytes/record and a pending window of 8 by default. Record counting includes zero-length/unsupported records. Global flow admission permits repeated existing keys at the limit. API file/request defaults are 25/26 MB, with 2 admitted requests, 8 workers/request and 16 total worker permits. Configuration keys and status mapping are in [API.md](API.md) and the [module README](../dpi-engine-api/README.md).

Memory includes capture byte arrays and defensive copies, parsed objects/futures, flow maps and retained reasons, servlet/JVM state and output buffers. Pending record count times the byte ceiling bounds pending captured data, not total heap. Flow memory grows with distinct keys. The API performs a complete prevalidation read, then processes in a second pass; it does not load the complete capture into a single application byte array. Multipart threshold is zero, so framework disk spooling can happen before service admission. There is no global temporary-disk quota or wall-clock deadline.

Bad framing/unsupported API link type gives 400; configured workload excess gives 413; media mismatch 415; busy admission 429; actual I/O failures 500. Core `DpiProcessingException` carries partial stats and output path; the API translates workload causes and does not expose partial success. Workspace cleanup tries every owned path and preserves primary failures. Filter holds files/permits through synchronous copying. [SEQUENCE.md](SEQUENCE.md) details committed-response and cleanup behavior.

## Security and operational limitations

Treat captures and extracted hostnames as sensitive user data. Uploads are untrusted: length checks, strict JSON and budgets reduce resource abuse but do not make this a production security gateway. Unsupported packets are deliberately allowed, and visible metadata can be missing or misleading. There is no malware detector, live enforcement, HTTPS decryption, authentication, persistent storage, ML model or external enrichment.

Default host binding is loopback. Compose also publishes only host loopback and runs non-root with a read-only filesystem and bounded writable tmpfs. Its memory/tmpfs limits may still produce I/O failure or process termination under pressure. Filesystem denial and crashes can leave workspaces; there is no background janitor. Slow downloads consume admission capacity, and post-commit failures may yield partial files without a replacement JSON error. See [DOCKER.md](../DOCKER.md) before changing limits or exposing the service.

