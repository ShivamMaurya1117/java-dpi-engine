Use new DpiEngine().process(new DpiEngineConfig(inputPath, outputPath, ruleSet)).
Null outputPath selects analysis only; new DpiEngineConfig(inputPath) also supplies
an empty RuleSet. The engine has no CLI dependencies, logging, or system exit calls.
Each process call creates fresh flow and rule state. The default threads value is 1
and retains the original sequential pipeline. Supply a fourth constructor argument
or --threads N to select 2..64 workers. A fifth config argument selects the bounded
queue/window capacity (1..4096; default 64). No worker shares mutable flow state.

The returned DpiProcessingResult contains immutable statistics and flow snapshots,
the input header, and the normalized output path (null for analysis only). A result
is returned only after reader and writer resources close successfully. Duration is
measured with System.nanoTime and includes file I/O and resource closure. Capture
timestamps continue to determine flow first/last timestamps.

Complete unsupported or malformed network packets are counted as skipped and are
allowed unchanged. Parsed packets use packet inspection plus
retained directional flow classification for rules; BLOCK stays sticky per flow.
Final application counts include each directional flow once. Blocking reason counts
may overlap. All input packets contribute to allowed or blocked counts; output mode
writes allowed packets in input order. Existing output files are never overwritten.

PCAP truncation and file I/O failures throw DpiProcessingException (an IOException)
with partialStats for complete records processed before failure. A truncated PCAP
record is reported as an error and cannot be counted as a fully read packet. No
successful result is returned. An indicated output may be incomplete; on flush
failure its partial written count means records submitted, not guaranteed on disk.

Parallel mode parses on the caller/coordinator thread, then dispatches a packet to
a single worker using a stable hash over all fields of the directional FlowKey.
Every input packet, including unsupported packets, receives a zero-based increasing
sequence number. Each worker owns one FIFO executor queue, classifier, FlowTracker,
and RuleManager. Its tasks run serially. The caller consumes pending futures in
sequence order and performs every PCAP write, including for unsupported packets.

The global pending window limits queued, active, and completed-but-unwritten packet
references together. It prevents unlimited reordering buffers and applies reader
backpressure even if the first worker is slow. Each worker queue is also bounded.
The coordinator checks for worker failures while waiting on earlier sequences.
Normal EOF drains every submitted task and joins the workers. Truncated input also
drains its complete records before reporting failure. Worker/write failures cancel
pending work, interrupt workers, and wait for termination; there is no fixed sleep.
Caller interruption is propagated and its interrupt status is restored. Worker
termination uses a shared 30-second deadline, followed by forced shutdown and a
second shared 30-second wait. Shutdown failures are suppressed onto an existing
processing failure rather than replacing it. Java cannot safely kill a worker
that ignores interruption; such a worker may outlive the failed call.

After joining, flow snapshots and final application counts are merged. All successful
run statistics and output bytes match sequential mode except processing duration.
Failure statistics may include dispatched packets and classifications ahead of the
last written sequence, and must not be treated as a successful complete result.

Limitations: reading, parsing, and writing remain serialized; a busy single flow
stays on one worker. Waiting for an early slow packet can reduce worker utilization.
The pending bound counts packets rather than bytes. Flow reporting retains
one entry per unique flow, so flow-table memory grows with unique flow count. No
performance speedup is claimed without benchmarks. Workers use direct dispatch and completion/join to finish pending work.

Optional resource budgets: a sixth DpiEngineConfig argument accepts
ProcessingLimits(maxPackets, maxFlows, maxPacketBytes). Record counts include
unsupported/zero-length records. Distinct parsed directional flows are admitted
before tracking; parallel admission happens on the coordinator, so maxFlows is
global rather than per worker. Captured-byte limits are enforced by PcapReader
before body allocation. Limit violations throw DpiProcessingException with a
ProcessingLimitException or PcapLimitException cause; partial output is not a
successful result. Existing config constructors retain their original behavior
(unrestricted record/flow counts and the existing 64 MiB reader ceiling). The API
explicitly supplies conservative budgets and a smaller pending window; the CLI
and unsupported-packet pass-through contract are unchanged.

PcapFormatException distinguishes invalid metadata from underlying storage I/O;
truncation still throws EOFException. Both remain IOException subclasses.


Reference attribution: [PROVENANCE.md](../../../../../../../PROVENANCE.md).
