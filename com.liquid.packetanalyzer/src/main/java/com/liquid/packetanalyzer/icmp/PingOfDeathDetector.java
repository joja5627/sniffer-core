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
import com.liquid.packetanalyzer.pcap_file.PacketInfo;
import com.liquid.packetanalyzer.pcap_file.AttackSummary;
import com.liquid.packetanalyzer.pcap_file.PcapFileSummary;
import org.apache.logging.log4j.core.Logger;
import org.pcap4j.packet.Packet;

/**
 * PingOfDeathDetector
 * <p/>
 * Detect Ping of Death attacks
 */
public class PingOfDeathDetector {
    private final static int MAX_PING_LENGTH = 65515;  // bytes
    private final static int MAX_PING_PAYLOAD = 65507; // bytes
    private static Logger log = Main.log;
    private boolean attackInProgress = false;
    private AttackSummary attackSummary = null;

    private boolean isPingOfDeath(Packet packet) {
        return (((packet.getRawData() != null) && (packet.getRawData().length > MAX_PING_LENGTH)) ||
                ((packet.getPayload() != null) && (packet.getPayload().getRawData() != null) &&
                        (packet.getPayload().getRawData().length > MAX_PING_PAYLOAD)));
    }

    public boolean detect(Packet packet, PcapFileSummary pcapFileSummary, PacketInfo packetInfo) {
        String sourceAddress = packetInfo.get(PacketInfo.SOURCE_ADDRESS);
        String destinationAddress = packetInfo.get(PacketInfo.DESTINATION_ADDRESS);

        if (isPingOfDeath(packet) && !attackInProgress) { // attack first detected
            log.trace("*** PING OF DEATH detected!");
            attackInProgress = true;
            attackSummary = new AttackSummary();
            attackSummary.setAttackName("PING OF DEATH");
            attackSummary.addSourceIpAndPort(sourceAddress);
            attackSummary.addTargetIpAndPort(destinationAddress);
            attackSummary.setStartTimestamp(packetInfo.get(PacketInfo.TIMESTAMP));
        } else if (isPingOfDeath(packet) && attackInProgress) { // add more details while attack in progress
            attackSummary.addSourceIpAndPort(sourceAddress);
            attackSummary.addTargetIpAndPort(destinationAddress);
        } else if (!isPingOfDeath(packet) && attackInProgress) { // attack ended, close out attack details
            attackInProgress = false;
            attackSummary.setEndTimestamp(packetInfo.get(PacketInfo.TIMESTAMP));
            pcapFileSummary.attackSummaries.add(attackSummary);
            this.attackSummary = null;
        }
        return this.attackInProgress;
    }
}
