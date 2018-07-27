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

package com.liquid.packetanalyzer.tcp;

import com.liquid.packetanalyzer.main.Main;
import com.liquid.packetanalyzer.pcap_file.PacketInfo;
import com.liquid.packetanalyzer.util.PacketInfoUtils;
import com.liquid.packetanalyzer.pcap_file.AttackSummary;
import com.liquid.packetanalyzer.pcap_file.PcapFileSummary;
import org.apache.logging.log4j.core.Logger;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.HashMap;
import java.util.LinkedHashSet;

/**
 * SynFloodDetector
 * <p/>
 * Detect SYN FLOOD attacks
 */
public class SynFloodDetector {
    private static final long LOOKBACK_WINDOW = 600; // milliseconds
    private static final int MAX_UNACKED_SYNS = 14;
    private static Logger log = Main.log;
    private final HashMap<String, LinkedHashSet<PacketInfo>> syns = new HashMap<>();

    private boolean attackInProgress = false;
    private AttackSummary attackSummary = null;

    public void detect(String serverAddress, PacketInfo packetInfo, PcapFileSummary pcapFileSummary) {
        // add the step1PacketInfo to the unACKed SYN packets for this IP address
        Instant currentTime = Timestamp.valueOf(packetInfo.get(PacketInfo.TIMESTAMP)).toInstant();
        Instant lookbackStart = currentTime.minusMillis(LOOKBACK_WINDOW);
        LinkedHashSet<PacketInfo> packetInfos = syns.get(serverAddress);
        if (packetInfos == null) {
            packetInfos = new LinkedHashSet<>();
            packetInfos.add(packetInfo);
        } else {
            // prune packetInfos that are beyond the lookback window
            LinkedHashSet<PacketInfo> keep = new LinkedHashSet<>();
            for (PacketInfo pi : packetInfos) {
                Instant packetTime = Timestamp.valueOf(pi.get(PacketInfo.TIMESTAMP)).toInstant();
                if (packetTime.isAfter(lookbackStart)) {
                    keep.add(pi);
                }
            }
            keep.add(packetInfo);
            packetInfos = keep;
        }
        syns.put(serverAddress, packetInfos);

        if (packetInfos.size() > MAX_UNACKED_SYNS && !attackInProgress) { // attack first detected
            log.trace("*** SYN FLOOD attack detected!");
            attackInProgress = true;
            attackSummary = new AttackSummary();
            attackSummary.setAttackName("SYN FLOOD");
            attackSummary.setStartTimestamp(PacketInfoUtils.getEarliest(packetInfos).get(PacketInfo.TIMESTAMP));
            for (PacketInfo info : packetInfos) {
                attackSummary.addSourceIpAndPort(info.get(PacketInfo.SOURCE_ADDRESS) + ":" + info.get(PacketInfo.SOURCE_PORT));
                attackSummary.addTargetIpAndPort(info.get(PacketInfo.DESTINATION_ADDRESS) + ":" + info.get(PacketInfo.DESTINATION_PORT));
            }
        } else if (packetInfos.size() > MAX_UNACKED_SYNS && attackInProgress) { // add more details while attack in progress
            for (PacketInfo info : packetInfos) {
                attackSummary.addSourceIpAndPort(info.get(PacketInfo.SOURCE_ADDRESS) + ":" + info.get(PacketInfo.SOURCE_PORT));
                attackSummary.addTargetIpAndPort(info.get(PacketInfo.DESTINATION_ADDRESS) + ":" + info.get(PacketInfo.DESTINATION_PORT));
            }
        } else if (packetInfos.size() <= MAX_UNACKED_SYNS && attackInProgress) { // attack ended, close out attack details
            attackInProgress = false;
            attackSummary.setEndTimestamp(PacketInfoUtils.getLatest(packetInfos).get(PacketInfo.TIMESTAMP));
            pcapFileSummary.attackSummaries.add(attackSummary);
            this.attackSummary = null;
        }
    }

    public void ackReceived(String serverAddress, PacketInfo step1PacketInfo) {
        LinkedHashSet<PacketInfo> synPacketInfos = syns.get(serverAddress);
        if (synPacketInfos != null) {
            synPacketInfos.remove(step1PacketInfo);

        }
    }
}
