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

package com.liquid.packetanalyzer.pcap_file;

import com.liquid.packetanalyzer.main.Main;
import com.liquid.packetanalyzer.tcp.IpAddressPair;
import org.apache.logging.log4j.core.Logger;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;

/**
 * PortScanDetector
 * <p/>
 * Tracks TCP and UDP traffic to detect port scanning
 */
public class PortScanDetector {
    /* We follow a modified version of the following heuristic for port scan detection:
     * "A portscan is detected when a detection score of 21 points
     * in a time range of 300 ms for one individual source IP address
     * is exceeded. The detection score is calculated as follows:
     * Scan of a TCP destination port less than 1024: 3 points
     * Scan of a TCP destination port greater or equal 1024: 1 point
     * Scan of ports 11, 12, 13, 2000: 10 points"
     * Source: https://community.sophos.com/kb/en-us/115153
     */
    private static final int DETECTION_SCORE = 42;
    private static final long LOOKBACK_WINDOW = 600; //milliseconds
    private static Logger log = Main.log;

    private boolean attackInProgress = false;
    private AttackSummary attackSummary = null;
    private final HashMap<IpAddressPair, LinkedHashSet<PacketInfo>> traffic = new HashMap<>();

    public void add(PacketInfo packetInfo, PcapFileSummary pcapFileSummary) {
        if (packetInfo == null) {
            throw new IllegalArgumentException("packetInfo cannot be null!");
        }
        // add the packetInfo
        String sourceAddress = packetInfo.get(PacketInfo.SOURCE_ADDRESS);
        String destinationAddress = packetInfo.get(PacketInfo.DESTINATION_ADDRESS);
        Instant currentTime = Timestamp.valueOf(packetInfo.get(PacketInfo.TIMESTAMP)).toInstant();
        Instant lookbackStart = currentTime.minusMillis(LOOKBACK_WINDOW);

        IpAddressPair ipAddressPair = new IpAddressPair(sourceAddress, destinationAddress);
        LinkedHashSet<PacketInfo> packetInfos = traffic.get(ipAddressPair);
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
        traffic.put(ipAddressPair, packetInfos);

        // calculate detection score
        HashSet<String> portSet = new HashSet<>();
        for (PacketInfo recentPi : packetInfos) {
            String destinationPort = recentPi.get(PacketInfo.DESTINATION_PORT);
            portSet.add(destinationPort);
        }
        if (portSet.size() >= DETECTION_SCORE && !attackInProgress) { // attack first detected
            log.trace("*** PORT SCANNING detected!");
            attackInProgress = true;
            attackSummary = new AttackSummary();
            attackSummary.setAttackName("PORT SCANNING");
            attackSummary.setStartTimestamp(lookbackStart.toString());
            for (PacketInfo info : packetInfos) {
                attackSummary.addSourceIpAndPort(info.get(PacketInfo.SOURCE_ADDRESS) + ":" + info.get(PacketInfo.SOURCE_PORT));
                attackSummary.addTargetIpAndPort(info.get(PacketInfo.DESTINATION_ADDRESS) + ":" + info.get(PacketInfo.DESTINATION_PORT));
            }
        } else if (portSet.size() >= DETECTION_SCORE && attackInProgress) { // add more details while attack in progress
            for (PacketInfo info : packetInfos) {
                attackSummary.addSourceIpAndPort(info.get(PacketInfo.SOURCE_ADDRESS) + ":" + info.get(PacketInfo.SOURCE_PORT));
                attackSummary.addTargetIpAndPort(info.get(PacketInfo.DESTINATION_ADDRESS) + ":" + info.get(PacketInfo.DESTINATION_PORT));
            }
        } else if (portSet.size() < DETECTION_SCORE && attackInProgress) { // attack ended, close out attack details
            attackInProgress = false;
            attackSummary.setEndTimestamp(currentTime.toString());
            pcapFileSummary.attackSummaries.add(attackSummary);
            this.attackSummary = null;
        }

    }
}
