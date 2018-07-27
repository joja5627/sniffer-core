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

package com.liquid.packetanalyzer.arp;

import com.liquid.packetanalyzer.main.Main;
import com.liquid.packetanalyzer.pcap_file.PcapFileSummary;
import org.apache.logging.log4j.core.Logger;
import org.pcap4j.packet.ArpPacket;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.namednumber.ArpOperation;
import org.pcap4j.util.MacAddress;

import java.net.InetAddress;

/**
 * ArpPacketProcessor
 * <p/>
 * Processes ARP packets
 */
public class ArpPacketProcessor {
    private static Logger log = Main.log;


    public static void processArpPacket(Packet packet, PcapFileSummary pcapFileSummary) {
        if (packet == null) {
            return; // skip empty packets
        }
        log.trace("Converting to ARP packet");
        try {
            ArpPacket arpPacket = ArpPacket.newPacket(packet.getRawData(), 0, packet.length());
            ArpPacket.ArpHeader arpHeader = arpPacket.getHeader();
            ArpOperation arpOperation = arpHeader.getOperation();
            InetAddress sourceIp = arpHeader.getSrcProtocolAddr();
            MacAddress sourceMac = arpHeader.getSrcHardwareAddr();

            if (arpOperation == ArpOperation.REQUEST) {
                // only add / check the source addresses for an ARP request
                //IpMacTrackerResult result = pcapFileSummary.ipMacTracker.query(sourceIp.getHostAddress(), sourceMac.toString());
            }

        } catch (IllegalRawDataException e) {
            log.error("Exception occurred while processing a packet. Exception was: " + e);
        }
    }
}
