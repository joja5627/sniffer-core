/*
 * Copyright (c) 2017.  Richard Scott McNew.
 *
 * This file is part of Liquid Fortress Packet Analyzer.
 *
 * Liquid Fortress Packet Analyzer is free software: you can redistribute
 * it and/or modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * Liquid Fortress Packet Analyzer is distributed in the hope that it will
 * be useful, but WITHOUT ANY WARRANTY; without even the implied
 * warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Liquid Fortress Packet Analyzer.
 * If not, see <http://www.gnu.org/licenses/>.
 */

package com.liquid.packetanalyzer.icmp;

import com.liquid.packetanalyzer.main.Main;
import com.liquid.packetanalyzer.main.Mode;
import com.liquid.packetanalyzer.pcap_file.PacketInfo;
import com.liquid.packetanalyzer.pcap_file.PcapFileSummary;
import org.apache.logging.log4j.core.Logger;
import org.pcap4j.packet.*;
import org.pcap4j.packet.namednumber.IcmpV4Type;
import org.pcap4j.packet.namednumber.IcmpV6Type;

/**
 * IcmpPacketProcessor
 * <p/>
 * Process ICMP packets
 */
public class IcmpPacketProcessor {
    private static Logger log = Main.log;


    public static void processIcmpv4Packet(Packet packet, PcapFileSummary pcapFileSummary, PacketInfo packetInfo, Mode mode) {
        if (packet == null) {
            return; // skip empty packets
        }
        String sourceAddress = packetInfo.get(PacketInfo.SOURCE_ADDRESS);
        String destinationAddress = packetInfo.get(PacketInfo.DESTINATION_ADDRESS);
        try {
            // detect Ping of Death
            if ((mode == Mode.POSSIBLE_ATTACKS_ANALYSIS) &&
                    (pcapFileSummary.pingOfDeathDetector.detect(packet, pcapFileSummary, packetInfo))) {
                return;
            }
            log.trace("Converting to ICMPv4 packet");
            IcmpV4CommonPacket icmpV4CommonPacket = IcmpV4CommonPacket.newPacket(packet.getRawData(), 0, packet.length());
            IcmpV4CommonPacket.IcmpV4CommonHeader icmpV4CommonHeader = icmpV4CommonPacket.getHeader();
            IcmpV4Type icmpV4Type = icmpV4CommonHeader.getType();
            if (icmpV4Type == IcmpV4Type.ECHO) {
                IcmpV4EchoPacket icmpV4EchoPacket = IcmpV4EchoPacket.newPacket(icmpV4CommonPacket.getRawData(), 0, icmpV4CommonPacket.length());
                IcmpV4EchoPacket.IcmpV4EchoHeader icmpV4EchoHeader = icmpV4EchoPacket.getHeader();
                short identifier = icmpV4EchoHeader.getIdentifier();
                short sequenceNumber = icmpV4EchoHeader.getSequenceNumber();
                log.trace("ICMPv4_ECHO_REQUEST{ source: " + sourceAddress + ", destination: " + destinationAddress +
                        ", identifier: " + identifier + ", seq number: " + sequenceNumber + " }");
            } else if (icmpV4Type == IcmpV4Type.ECHO_REPLY) {
                IcmpV4EchoReplyPacket icmpV4EchoReplyPacket = IcmpV4EchoReplyPacket.newPacket(icmpV4CommonPacket.getRawData(), 0, icmpV4CommonPacket.length());
                IcmpV4EchoReplyPacket.IcmpV4EchoReplyHeader icmpV4EchoReplyHeader = icmpV4EchoReplyPacket.getHeader();
                short identifier = icmpV4EchoReplyHeader.getIdentifier();
                short sequenceNumber = icmpV4EchoReplyHeader.getSequenceNumber();
                log.trace("ICMPv4_ECHO_REPLY{ source: " + sourceAddress + ", destination: " + destinationAddress +
                        ", identifier: " + identifier + ", seq number: " + sequenceNumber + " }");
                // detect SMURF attack
                if (mode == Mode.POSSIBLE_ATTACKS_ANALYSIS) {
                    pcapFileSummary.smurfDetector.add(packetInfo, pcapFileSummary);
                }
            } else {
                log.trace("Other ICMPv4 packet with type: " + icmpV4Type);
            }
        } catch (IllegalRawDataException e) {
            log.error("Exception occurred while processing a packet. Exception was: " + e);
        }
    }

    public static void processIcmpv6Packet(Packet packet, PcapFileSummary pcapFileSummary, PacketInfo packetInfo, Mode mode) {
        if (packet == null) {
            return; // skip empty packets
        }
        String sourceAddress = packetInfo.get(PacketInfo.SOURCE_ADDRESS);
        String destinationAddress = packetInfo.get(PacketInfo.DESTINATION_ADDRESS);
        try {
            log.trace("Converting to ICMPv6 packet");
            IcmpV6CommonPacket icmpV6CommonPacket = IcmpV6CommonPacket.newPacket(packet.getRawData(), 0, packet.length());
            IcmpV6CommonPacket.IcmpV6CommonHeader icmpV6CommonHeader = icmpV6CommonPacket.getHeader();
            IcmpV6Type icmpV6Type = icmpV6CommonHeader.getType();
            if (icmpV6Type == IcmpV6Type.ECHO_REQUEST) {
                IcmpV6EchoRequestPacket icmpV6EchoRequestPacket = IcmpV6EchoRequestPacket.newPacket(icmpV6CommonPacket.getRawData(), 0, icmpV6CommonPacket.length());
                IcmpV6EchoRequestPacket.IcmpV6EchoRequestHeader icmpV6EchoRequestHeader = icmpV6EchoRequestPacket.getHeader();
                short identifier = icmpV6EchoRequestHeader.getIdentifier();
                short sequenceNumber = icmpV6EchoRequestHeader.getSequenceNumber();
                log.trace("ICMPv6_ECHO_REQUEST{ source: " + sourceAddress + ", destination: " + destinationAddress +
                        ", identifier: " + identifier + ", seq number: " + sequenceNumber + " }");
            } else if (icmpV6Type == IcmpV6Type.ECHO_REPLY) {
                IcmpV6EchoReplyPacket icmpV6EchoReplyPacket = IcmpV6EchoReplyPacket.newPacket(icmpV6CommonPacket.getRawData(), 0, icmpV6CommonPacket.length());
                IcmpV6EchoReplyPacket.IcmpV6EchoReplyHeader icmpV6EchoReplyHeader = icmpV6EchoReplyPacket.getHeader();
                short identifier = icmpV6EchoReplyHeader.getIdentifier();
                short sequenceNumber = icmpV6EchoReplyHeader.getSequenceNumber();
                log.trace("ICMPv6_ECHO_REPLY{ source: " + sourceAddress + ", destination: " + destinationAddress +
                        ", identifier: " + identifier + ", seq number: " + sequenceNumber + " }");
            } else {
                log.trace("Other ICMPv6 packet with type: " + icmpV6Type);
            }
        } catch (IllegalRawDataException e) {
            log.error("Exception occurred while processing a packet. Exception was: " + e);
        }
    }
}
