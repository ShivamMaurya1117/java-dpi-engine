package com.dpiengine.flow;

import com.dpiengine.packet.ParsedPacket;
import java.util.Objects;

/** Immutable directional five-tuple; record equality and hashing include all five fields. */
public record FlowKey(String sourceIp, String destinationIp, int sourcePort,
                      int destinationPort, int protocol) {
    public FlowKey {
        Objects.requireNonNull(sourceIp, "sourceIp");
        Objects.requireNonNull(destinationIp, "destinationIp");
        if (sourcePort < 0 || sourcePort > 65535 || destinationPort < 0 || destinationPort > 65535) {
            throw new IllegalArgumentException("Ports must be unsigned 16-bit values");
        }
        if (protocol < 0 || protocol > 255) {
            throw new IllegalArgumentException("Protocol must be an unsigned 8-bit value");
        }
    }

    public static FlowKey from(ParsedPacket packet) {
        return new FlowKey(packet.sourceIp(), packet.destinationIp(), packet.sourcePort(),
                packet.destinationPort(), packet.protocol());
    }

    @Override
    public String toString() {
        return sourceIp + ":" + sourcePort + " -> " + destinationIp + ":" + destinationPort
                + " protocol=" + protocol;
    }
}
