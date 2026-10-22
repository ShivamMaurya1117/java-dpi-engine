package com.dpiengine.packet;

import java.time.Instant;

/** Validated Ethernet/IPv4/TCP or UDP metadata. Offsets refer to the captured raw bytes. */
public record ParsedPacket(Instant timestamp, String sourceMac, String destinationMac,
                           int etherType, String sourceIp, String destinationIp,
                           int protocol, int ttl, int sourcePort, int destinationPort,
                           int tcpFlags, long sequenceNumber, long acknowledgmentNumber,
                           int ipHeaderLength, int transportOffset, int transportHeaderLength,
                           int payloadOffset, int payloadLength) {
    public boolean isTcp() { return protocol == PacketParser.TCP; }
    public boolean isUdp() { return protocol == PacketParser.UDP; }
}
