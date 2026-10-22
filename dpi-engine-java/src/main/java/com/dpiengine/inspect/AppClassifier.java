package com.dpiengine.inspect;

import com.dpiengine.packet.ParsedPacket;
import com.dpiengine.pcap.CapturedPacket;
import java.util.List;
import java.util.Optional;

/** Packet-local inspection using explicit domain roots for the original applications.
 * Only exact roots and their subdomains match; arbitrary brand substrings do not.
 */
public final class AppClassifier {
    private record Mapping(AppType app, List<String> domains) { }
    private static Mapping rule(AppType app, String... domains) {
        return new Mapping(app, List.of(domains));
    }
    private static final List<Mapping> MAPPINGS = List.of(
            rule(AppType.GOOGLE, "google.com", "gstatic.com", "googleapis.com", "ggpht.com", "gvt1.com"),
            rule(AppType.YOUTUBE, "youtube.com", "ytimg.com", "youtu.be"),
            rule(AppType.FACEBOOK, "facebook.com", "fbcdn.net", "fb.com", "fbsbx.com", "meta.com"),
            rule(AppType.INSTAGRAM, "instagram.com", "cdninstagram.com"),
            rule(AppType.WHATSAPP, "whatsapp.com", "whatsapp.net", "wa.me"),
            rule(AppType.TWITTER, "twitter.com", "twimg.com", "x.com", "t.co"),
            rule(AppType.NETFLIX, "netflix.com", "netflix.net", "nflxvideo.net", "nflximg.net", "nflximg.com"),
            rule(AppType.AMAZON, "amazon.com", "amazonaws.com", "cloudfront.net", "aws.com"),
            rule(AppType.MICROSOFT, "microsoft.com", "msn.com", "office.com", "office365.com", "azure.com",
                    "live.com", "outlook.com", "bing.com"),
            rule(AppType.APPLE, "apple.com", "icloud.com", "mzstatic.com", "itunes.com"),
            rule(AppType.TELEGRAM, "telegram.org", "t.me"),
            rule(AppType.TIKTOK, "tiktok.com", "tiktokcdn.com", "musical.ly", "bytedance.com"),
            rule(AppType.SPOTIFY, "spotify.com", "scdn.co"), rule(AppType.ZOOM, "zoom.us", "zoom.com"),
            rule(AppType.DISCORD, "discord.com", "discordapp.com"),
            rule(AppType.GITHUB, "github.com", "githubusercontent.com"),
            rule(AppType.CLOUDFLARE, "cloudflare.com"));

    private final TlsSniExtractor tls = new TlsSniExtractor();
    private final HttpHostExtractor http = new HttpHostExtractor();
    private final DnsQueryExtractor dns = new DnsQueryExtractor();

    public AppType classifyDomain(String hostname, AppType fallback) {
        if (hostname == null) return fallback;
        Optional<String> normalized = Hostnames.normalize(hostname);
        if (normalized.isEmpty()) return fallback;
        String domain = normalized.orElseThrow();
        for (Mapping mapping : MAPPINGS) {
            if (mapping.domains().stream().anyMatch(root -> domain.equals(root) || domain.endsWith("." + root))) {
                return mapping.app();
            }
        }
        return fallback;
    }

    public AppType fallback(ParsedPacket packet) {
        if ((packet.isTcp() || packet.isUdp()) && port(packet, 53)) return AppType.DNS;
        if (packet.isTcp() && port(packet, 443)) return AppType.HTTPS;
        if (packet.isTcp() && port(packet, 80)) return AppType.HTTP;
        return AppType.UNKNOWN;
    }

    public InspectionResult inspect(CapturedPacket captured, ParsedPacket packet) {
        AppType generic = fallback(packet);
        byte[] data = captured.rawBytes();
        int offset = packet.payloadOffset(), length = packet.payloadLength();
        if (offset < 0 || length < 0 || offset > data.length || length > data.length - offset) {
            return new InspectionResult(generic, "");
        }
        Optional<String> hostname = Optional.empty();
        if (generic == AppType.DNS) {
            if (packet.isTcp()) {
                // Only complete DNS messages in this packet; no stream reassembly.
                if (length >= 2) {
                    int messageLength = (Byte.toUnsignedInt(data[offset]) << 8) | Byte.toUnsignedInt(data[offset + 1]);
                    if (messageLength <= length - 2) hostname = dns.extract(data, offset + 2, messageLength);
                }
            } else {
                hostname = dns.extract(data, offset, length);
            }
        } else if (packet.isTcp()) {
            hostname = tls.extract(data, offset, length);
            if (hostname.isPresent()) {
                generic = AppType.HTTPS;
            } else {
                hostname = http.extract(data, offset, length);
                if (hostname.isPresent()) generic = AppType.HTTP;
            }
        }
        String name = hostname.orElse("");
        return new InspectionResult(classifyDomain(name, generic), name);
    }

    private static boolean port(ParsedPacket packet, int port) {
        return packet.sourcePort() == port || packet.destinationPort() == port;
    }
}
