Application inspection is packet-local. AppClassifier.inspect uses only the payload
offset and length supplied by ParsedPacket. The extractors return Optional.empty
for incomplete, malformed, or unsupported payloads. They do not decrypt TLS or
reassemble TCP streams. TLS requires a complete ClientHello within one record.
HTTP requires a complete HTTP/1 request header block (maximum 64 KiB); bodies are
never searched. DNS requires complete questions and safely rejects compression
pointers in question names. TCP DNS uses its two-byte message-length prefix.

The mapping table uses explicit domain roots. Names are validated, lowercased, and stripped of a trailing DNS root
dot before matching. A name must equal a listed root or end in a dot followed by
that root. Brand fragments cannot identify an application.
For example, www.youtube.com matches youtube.com, while notyoutube.com and
youtube.com.evil.example do not. Unlisted domain roots use the generic fallback.
Mapping order determines precedence; yt3.ggpht.com matches GOOGLE through ggpht.com.
TLS and QUIC enum values are retained for compatibility but are not emitted by the classifier. Unrecognized hostnames retain HTTP, HTTPS, DNS, or UNKNOWN according
to their protocol context. Port-based fallbacks inspect both endpoints; UDP/443
alone does not imply HTTPS.

FlowTracker.track(CapturedPacket, ParsedPacket) counts and inspects one packet.
The original track(ParsedPacket, long) overload still counts packets and supplies
port-based fallback classifications. FlowState snapshots contain appType and
hostname. Generic classifications remain eligible for upgrades even after an
unmapped hostname was extracted. The first specific application and its hostname
are retained; subsequent packets still update statistics. Reverse traffic remains
a separate flow and does not inherit the forward flow's classification.

Application distributions count final classifications once per directional flow.
Thus mapped DNS queries may appear under a specific application rather than DNS;
the generic DNS category includes only flows without a recognized application.


Reference attribution: [PROVENANCE.md](../../../../../../../PROVENANCE.md).
