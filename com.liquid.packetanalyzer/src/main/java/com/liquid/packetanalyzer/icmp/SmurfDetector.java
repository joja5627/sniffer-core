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

import java.sql.Timestamp;
import java.time.Instant;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;

/**
 * SmurfDetector
 * <p/>
 * Detect smurf attacks
 */
public class SmurfDetector {
    private static final int DETECTION_SCORE = 21;
    private static final long LOOKBACK_WINDOW = 600; //milliseconds
    private static Logger log = Main.log;
    private final HashMap<String, LinkedHashSet<PacketInfo>> recentEchoReplies = new HashMap<>();
    private boolean attackInProgress = false;
    private AttackSummary attackSummary = null;

    public void add(PacketInfo packetInfo, PcapFileSummary pcapFileSummary) {
        if (packetInfo == null) {
            throw new IllegalArgumentException("packetInfo cannot be null!");
        }
        // add the packetInfo
        String destinationAddress = packetInfo.get(PacketInfo.DESTINATION_ADDRESS);
        Instant currentTime = Timestamp.valueOf(packetInfo.get(PacketInfo.TIMESTAMP)).toInstant();
        Instant lookbackStart = currentTime.minusMillis(LOOKBACK_WINDOW);

        LinkedHashSet<PacketInfo> packetInfos = recentEchoReplies.get(destinationAddress);
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
        recentEchoReplies.put(destinationAddress, packetInfos);

        // calculate detection score
        HashSet<String> sourceAddressSet = new HashSet<>();
        for (PacketInfo recentPi : packetInfos) {
            String sourceAddress = recentPi.get(PacketInfo.SOURCE_ADDRESS);
            sourceAddressSet.add(sourceAddress);
        }
        if (sourceAddressSet.size() >= DETECTION_SCORE && !attackInProgress) { // attack first detected
            log.trace("*** SMURF ATTACK detected!");
            attackInProgress = true;
            attackSummary = new AttackSummary();
            attackSummary.setAttackName("SMURF ATTACK");
            attackSummary.setStartTimestamp(lookbackStart.toString());
            for (PacketInfo info : packetInfos) {
                attackSummary.addSourceIpAndPort(info.get(PacketInfo.SOURCE_ADDRESS));
                attackSummary.addTargetIpAndPort(info.get(PacketInfo.DESTINATION_ADDRESS));
            }
        } else if (sourceAddressSet.size() >= DETECTION_SCORE && attackInProgress) { // add more details while attack in progress
            for (PacketInfo info : packetInfos) {
                attackSummary.addSourceIpAndPort(info.get(PacketInfo.SOURCE_ADDRESS));
                attackSummary.addTargetIpAndPort(info.get(PacketInfo.DESTINATION_ADDRESS));
            }
        } else if (sourceAddressSet.size() < DETECTION_SCORE && attackInProgress) { // attack ended, close out attack details
            attackInProgress = false;
            attackSummary.setEndTimestamp(currentTime.toString());
            pcapFileSummary.attackSummaries.add(attackSummary);
            this.attackSummary = null;
        }
    }
}
