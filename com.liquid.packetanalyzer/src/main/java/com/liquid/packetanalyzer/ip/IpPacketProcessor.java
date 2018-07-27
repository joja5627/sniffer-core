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

package com.liquid.packetanalyzer.ip;

import com.liquid.packetanalyzer.icmp.IcmpPacketProcessor;
import com.liquid.packetanalyzer.main.Main;
import com.liquid.packetanalyzer.main.Mode;
import com.liquid.packetanalyzer.pcap_file.PacketInfo;
import com.liquid.packetanalyzer.tcp.TcpPacketProcessor;
import com.liquid.packetanalyzer.udp.UdpPacketProcessor;
import com.liquid.packetanalyzer.pcap_file.PcapFileSummary;
import org.apache.logging.log4j.core.Logger;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV6Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.namednumber.IpNumber;

import java.net.Inet4Address;
import java.net.Inet6Address;

/**
 * IpPacketProcessor
 * <p/>
 * Processes IP packets
 */
public class IpPacketProcessor {
    private static Logger log = Main.log;


    public static void processIpv4Packet(Packet packet, PcapFileSummary pcapFileSummary, PacketInfo packetInfo, Mode mode) {
        if (packet == null) {
            return; // skip empty packets
        }
        try {
            log.trace("Converting to IPv4 packet");
            IpV4Packet ipV4Packet = IpV4Packet.newPacket(packet.getRawData(), 0, packet.length());
            IpV4Packet.IpV4Header ipV4Header = ipV4Packet.getHeader();
            boolean fragmented = ipV4Header.getMoreFragmentFlag() || (ipV4Header.getFragmentOffset() > 0);
            try {
                if (fragmented) {
                    int identification = ipV4Header.getIdentificationAsInt();
                    pcapFileSummary.ipDefragmenter.addFragment(identification, ipV4Packet);
                    if ((!ipV4Header.getMoreFragmentFlag()) && (ipV4Header.getFragmentOffset() > 0)) {
                        ipV4Packet = pcapFileSummary.ipDefragmenter.defragment(identification);
                        ipV4Header = ipV4Packet.getHeader();
                        packetInfo.put(PacketInfo.IP_IDENTIFICATION, Integer.toString(identification));
                        packetInfo.put(PacketInfo.WAS_FRAGMENTED, Boolean.TRUE.toString());
                    } else {
                        return; // we need all the fragments before this packet can be processed further
                    }
                }
            } catch (IllegalArgumentException e) {
                log.trace("Exception occurred while processing a packet. Exception was: " + e);
                return;
            }
            Inet4Address sourceAddress = ipV4Header.getSrcAddr();
            Inet4Address destAddress = ipV4Header.getDstAddr();

            if (mode == Mode.POSSIBLE_ATTACKS_ANALYSIS) {
                //pcapFileSummary.ipMacTracker.query(sourceAddress.getHostAddress(), sourceMac.toString());
            }
            packetInfo.put(PacketInfo.SOURCE_ADDRESS, sourceAddress.getHostAddress());
            packetInfo.put(PacketInfo.DESTINATION_ADDRESS, destAddress.getHostAddress());
            log.trace("Adding IPv4 addresses to set:  source: " + sourceAddress.getHostAddress() + ", dest: " + destAddress.getHostAddress());
            pcapFileSummary.uniqueIpAddresses.add(sourceAddress.getHostAddress());
            pcapFileSummary.uniqueIpAddresses.add(destAddress.getHostAddress());
            IpNumber ipNumber = ipV4Header.getProtocol();
            packetInfo.put(PacketInfo.IP_PROTOCOL, ipNumber.toString());
            pcapFileSummary.ipProtocolCounter.increment(ipNumber);
            Packet payload = ipV4Packet.getPayload();
            if (ipNumber == IpNumber.ICMPV4) {
                IcmpPacketProcessor.processIcmpv4Packet(payload, pcapFileSummary, packetInfo, mode);
            } else if (ipNumber == IpNumber.ICMPV6) {
                IcmpPacketProcessor.processIcmpv6Packet(payload, pcapFileSummary, packetInfo, mode);
            } else if (ipNumber == IpNumber.TCP) {
                TcpPacketProcessor.processTcpPacket(payload, pcapFileSummary, packetInfo, mode);
            } else if (ipNumber == IpNumber.UDP) {
                UdpPacketProcessor.processUdpPacket(payload, pcapFileSummary, packetInfo, mode);
            } else {
                log.trace("Skipping packet: " + payload);
            }
        } catch (IllegalRawDataException e) {
            log.error("Exception occurred while processing a packet. Exception was: " + e);
        }
    }

    public static void processIpv6Packet(Packet packet, PcapFileSummary pcapFileSummary, PacketInfo packetInfo, Mode mode) {
        if (packet == null) {
            return; // skip empty packets
        }
        try {
            log.trace("Converting to IPv6 packet");
            IpV6Packet ipV6Packet = IpV6Packet.newPacket(packet.getRawData(), 0, packet.length());
            IpV6Packet.IpV6Header ipV6Header = ipV6Packet.getHeader();
            Inet6Address sourceAddress = ipV6Header.getSrcAddr();
            Inet6Address destAddress = ipV6Header.getDstAddr();
            if (mode == Mode.POSSIBLE_ATTACKS_ANALYSIS) {
                //pcapFileSummary.ipMacTracker.query(sourceAddress.getHostAddress(), sourceMac.toString());
            }
            packetInfo.put(PacketInfo.SOURCE_ADDRESS, sourceAddress.getHostAddress());
            packetInfo.put(PacketInfo.DESTINATION_ADDRESS, destAddress.getHostAddress());
            log.trace("Adding IPv6 addresses to set:  source: " + sourceAddress.getHostAddress() + ", dest: " + destAddress.getHostAddress());
            pcapFileSummary.uniqueIpAddresses.add(sourceAddress.getHostAddress());
            pcapFileSummary.uniqueIpAddresses.add(destAddress.getHostAddress());
            IpNumber ipNumber = ipV6Header.getProtocol();
            packetInfo.put(PacketInfo.IP_PROTOCOL, ipNumber.toString());
            pcapFileSummary.ipProtocolCounter.increment(ipNumber);
            Packet payload = ipV6Packet.getPayload();
            if (ipNumber == IpNumber.ICMPV4) {
                IcmpPacketProcessor.processIcmpv4Packet(payload, pcapFileSummary, packetInfo, mode);
            } else if (ipNumber == IpNumber.ICMPV6) {
                IcmpPacketProcessor.processIcmpv6Packet(payload, pcapFileSummary, packetInfo, mode);
            } else if (ipNumber == IpNumber.TCP) {
                TcpPacketProcessor.processTcpPacket(payload, pcapFileSummary, packetInfo, mode);
            } else if (ipNumber == IpNumber.UDP) {
                UdpPacketProcessor.processUdpPacket(payload, pcapFileSummary, packetInfo, mode);
            } else {
                log.trace("Skipping packet: " + payload);
            }
        } catch (IllegalRawDataException e) {
            log.error("Exception occurred while processing a packet. Exception was: " + e);
        }
    }
}
