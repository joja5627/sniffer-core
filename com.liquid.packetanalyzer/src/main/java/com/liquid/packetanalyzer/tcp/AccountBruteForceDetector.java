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
import org.pcap4j.packet.Packet;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.LinkedList;

/**
 * AccountBruteForceDetector
 * <p/>
 * Detects brute force and dictionary attacks against Telnet
 */
public class AccountBruteForceDetector {
    private static final int TELNET_PORT = 23;
    private static final long LOOKBACK_WINDOW = 30000; //milliseconds
    private static final int DETECTION_SCORE = 4;
    private static Logger log = Main.log;
    // watchList tracks which IP address pairs we are watching and the PacketInfos since we started watching
    private HashMap<IpAddressPair, LinkedHashSet<PacketInfo>> watchList = new HashMap<>();
    // packetData stores the captured packet data from telnet; we will assemble this data into usernames and passwords
    // since there could be multiple ports active simultaneously, we store data per port
    private HashMap<IpAddressPair, HashMap<Integer, String>> packetData = new HashMap<>();
    // telnetLoginsInProgress stores the captured username data on a per source port basis
    // after the telnet daemon response is captured, the username data is either cleared or
    // matched with the password and transferred to failedAttempts
    private HashMap<IpAddressPair, HashMap<Integer, TelnetLoginAttempt>> telnetLoginsInProgress = new HashMap<>();
    // failedAttempts stores the data from past failed telnet login attempts and counts how many failed attempts have occurred
    // if more than DETECTION_SCORE attempts have occurred, the alert is triggered
    private HashMap<IpAddressPair, LinkedList<TelnetLoginAttempt>> failedAttempts = new HashMap<>();
    private boolean attackInProgress = false;
    private AttackSummary attackSummary = null;

    private boolean underAttack(IpAddressPair ipAddressPair) {
        LinkedList<TelnetLoginAttempt> attempts = failedAttempts.get(ipAddressPair);
        return ((attempts != null) && (attempts.size() >= DETECTION_SCORE));
    }

    private void addToWatchList(IpAddressPair ipAddressPair, PacketInfo packetInfo) {
        LinkedHashSet<PacketInfo> packetInfos = watchList.get(ipAddressPair);
        if (packetInfos == null) {
            packetInfos = new LinkedHashSet<>();
        }
        packetInfos.add(packetInfo);
        watchList.put(ipAddressPair, packetInfos);
    }

    private void removeFromWatchList(IpAddressPair ipAddressPair) {
        watchList.remove(ipAddressPair);
    }

    private boolean onWatchlist(IpAddressPair ipAddressPair) {
        return watchList.containsKey(ipAddressPair);
    }

    private String processBackspace(String input) {
        StringBuilder sb = new StringBuilder();
        for (char c : input.toCharArray()) {
            if (c == '\b') {
                if (sb.length() > 0) {
                    sb.deleteCharAt(sb.length() - 1);
                }
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    private String cleanStr(String str) {
        return processBackspace(str).replaceAll("\\p{Cntrl}", "");
    }

    private void capturePacketData(IpAddressPair ipAddressPair, int senderPort, String payloadStr) {
        HashMap<Integer, String> portsData = packetData.get(ipAddressPair);
        if (portsData == null) {
            portsData = new HashMap<>();
        }
        // clean up payloadStr

        String data = portsData.get(senderPort);
        if (data == null) {
            data = payloadStr;
        } else {
            data += payloadStr;
        }
        portsData.put(senderPort, data);
        packetData.put(ipAddressPair, portsData);
    }

    private String getCapturedPacketData(IpAddressPair ipAddressPair, int senderPort) {
        HashMap<Integer, String> portsData = packetData.get(ipAddressPair);
        if (portsData != null) {
            return cleanStr(portsData.get(senderPort));
        } else {
            return null;
        }
    }

    private void clearCapturedPacketData(IpAddressPair ipAddressPair, int senderPort) {
        HashMap<Integer, String> portsData = packetData.get(ipAddressPair);
        if (portsData != null) {
            portsData.remove(senderPort);
        }
    }

    private void storeUsername(IpAddressPair ipAddressPair, int senderPort, String username) {
        // store the captured username in telnetLoginsInProgress
        HashMap<Integer, TelnetLoginAttempt> portsUsernames = telnetLoginsInProgress.get(ipAddressPair);
        if (portsUsernames == null) {
            portsUsernames = new HashMap<>();
        }
        TelnetLoginAttempt loginAttempt = portsUsernames.get(senderPort);
        if (loginAttempt == null) {
            loginAttempt = new TelnetLoginAttempt();
        }
        loginAttempt.username = username;
        portsUsernames.put(senderPort, loginAttempt);
        telnetLoginsInProgress.put(ipAddressPair, portsUsernames);
    }

    private void storePassword(IpAddressPair ipAddressPair, int senderPort, String password, String timestamp) {
        // store the captured password in telnetLoginsInProgress
        HashMap<Integer, TelnetLoginAttempt> portsUsernames = telnetLoginsInProgress.get(ipAddressPair);
        if (portsUsernames == null) {
            portsUsernames = new HashMap<>();
        }
        TelnetLoginAttempt loginAttempt = portsUsernames.get(senderPort);
        if (loginAttempt == null) {
            loginAttempt = new TelnetLoginAttempt();
        }
        loginAttempt.password = password;
        loginAttempt.timestamp = timestamp;
        portsUsernames.put(senderPort, loginAttempt);
        telnetLoginsInProgress.put(ipAddressPair, portsUsernames);
    }

    private void moveTelnetLoginAttemptToFailedAttempts(IpAddressPair ipAddressPair, int senderPort) {
        HashMap<Integer, TelnetLoginAttempt> portsUsernames = telnetLoginsInProgress.get(ipAddressPair);
        TelnetLoginAttempt loginAttempt = portsUsernames.get(senderPort);

        LinkedList<TelnetLoginAttempt> attempts = failedAttempts.get(ipAddressPair);
        if (attempts == null) {
            attempts = new LinkedList<>();
        }
        attempts.add(loginAttempt);
        failedAttempts.put(ipAddressPair, attempts);
        portsUsernames.remove(senderPort);
    }

    private void removeTelnetLoginAttempt(IpAddressPair ipAddressPair, int senderPort) {
        HashMap<Integer, TelnetLoginAttempt> portsUsernames = telnetLoginsInProgress.get(ipAddressPair);
        if (portsUsernames != null) {
            portsUsernames.remove(senderPort);
        }
    }


    public void detect(Packet packet, PacketInfo packetInfo, PcapFileSummary pcapFileSummary) {
        if (packetInfo == null) {
            throw new IllegalArgumentException("packetInfo cannot be null!");
        }
        // extract common data
        String sourceAddress = packetInfo.get(PacketInfo.SOURCE_ADDRESS);
        String destinationAddress = packetInfo.get(PacketInfo.DESTINATION_ADDRESS);
        int sourcePort = Integer.parseInt(packetInfo.get(PacketInfo.SOURCE_PORT));
        int destinationPort = Integer.parseInt(packetInfo.get(PacketInfo.DESTINATION_PORT));
        Instant currentTime = Timestamp.valueOf(packetInfo.get(PacketInfo.TIMESTAMP)).toInstant();
        Instant lookbackStart = currentTime.minusMillis(LOOKBACK_WINDOW);
        IpAddressPair ipAddressPair = new IpAddressPair(sourceAddress, destinationAddress);
        String str = null;
        if (packet != null && packet.getRawData() != null) {
            str = new String(packet.getRawData());
        } else {
            return; // if there is no packet data, stop processing
        }

        if (onWatchlist(ipAddressPair)) {
            // prune failedAttempts and watchList packetInfos that are beyond the lookback window
            //// first prune watchList packetInfos
            LinkedHashSet<PacketInfo> wlPacketInfos = watchList.get(ipAddressPair);
            if (wlPacketInfos != null && !wlPacketInfos.isEmpty()) {
                LinkedHashSet<PacketInfo> keep = new LinkedHashSet<>();
                for (PacketInfo pi : wlPacketInfos) {
                    Instant packetTime = Timestamp.valueOf(pi.get(PacketInfo.TIMESTAMP)).toInstant();
                    if (packetTime.isAfter(lookbackStart)) {
                        keep.add(pi);
                    }
                }
                if (keep.isEmpty()) {
                    removeFromWatchList(ipAddressPair);
                } else {
                    watchList.put(ipAddressPair, keep);
                }
            }
            //// next prune failedAttempts
            LinkedList<TelnetLoginAttempt> ipFailedAttempts = failedAttempts.get(ipAddressPair);
            if (ipFailedAttempts != null && !ipFailedAttempts.isEmpty()) {
                LinkedList<TelnetLoginAttempt> keepAttempts = new LinkedList<>();
                for (TelnetLoginAttempt attempt : ipFailedAttempts) {
                    Instant attemptTime = Timestamp.valueOf(attempt.timestamp).toInstant();
                    if (attemptTime.isAfter(lookbackStart)) {
                        keepAttempts.add(attempt);
                    }
                }
                if (keepAttempts.isEmpty()) {
                    failedAttempts.remove(ipAddressPair);
                } else {
                    failedAttempts.put(ipAddressPair, keepAttempts);
                }
            }
            // trigger if beyond threshold
            if (underAttack(ipAddressPair) && !attackInProgress) {
                log.trace("*** BRUTE FORCE / DICTIONARY ATTACK detected!");
                attackInProgress = true;
                attackSummary = new AttackSummary();
                attackSummary.setAttackName("BRUTE FORCE / DICTIONARY ATTACK");
                attackSummary.setStartTimestamp(PacketInfoUtils.getEarliest(watchList.get(ipAddressPair)).get(PacketInfo.TIMESTAMP));
                LinkedHashSet<PacketInfo> packetInfos = watchList.get(ipAddressPair);
                for (PacketInfo info : packetInfos) {
                    attackSummary.addSourceIpAndPort(info.get(PacketInfo.SOURCE_ADDRESS) + ":" + info.get(PacketInfo.SOURCE_PORT));
                    attackSummary.addTargetIpAndPort(info.get(PacketInfo.DESTINATION_ADDRESS) + ":" + info.get(PacketInfo.DESTINATION_PORT));
                }
                LinkedList<TelnetLoginAttempt> attempts = failedAttempts.get(ipAddressPair);
                for (TelnetLoginAttempt attempt : attempts) {
                    attackSummary.addUsernameAndPassword(attempt.username + ":" + attempt.password);
                }
            } else if (underAttack(ipAddressPair) && attackInProgress) {
                LinkedHashSet<PacketInfo> packetInfos = watchList.get(ipAddressPair);
                for (PacketInfo info : packetInfos) {
                    attackSummary.addSourceIpAndPort(info.get(PacketInfo.SOURCE_ADDRESS) + ":" + info.get(PacketInfo.SOURCE_PORT));
                    attackSummary.addTargetIpAndPort(info.get(PacketInfo.DESTINATION_ADDRESS) + ":" + info.get(PacketInfo.DESTINATION_PORT));
                }
                attackSummary.setEndTimestamp(PacketInfoUtils.getLatest(watchList.get(ipAddressPair)).get(PacketInfo.TIMESTAMP));
                LinkedList<TelnetLoginAttempt> attempts = failedAttempts.get(ipAddressPair);
                for (TelnetLoginAttempt attempt : attempts) {
                    attackSummary.addUsernameAndPassword(attempt.username + ":" + attempt.password);
                }
            } else if (!underAttack(ipAddressPair) && attackInProgress) {
                attackInProgress = false;
                if (watchList.get(ipAddressPair) != null) {
                    attackSummary.setEndTimestamp(PacketInfoUtils.getLatest(watchList.get(ipAddressPair)).get(PacketInfo.TIMESTAMP));
                }
                pcapFileSummary.attackSummaries.add(attackSummary);
                this.attackSummary = null;
            }
        }
        // filter out packets that are not to / from telnet port 23
        if (sourcePort == TELNET_PORT) { // the telnet server is sending
            if (str.contains("login:")) {
                // Add this IP pair to the watch list, log the data to monitor the login for failure
                addToWatchList(ipAddressPair, packetInfo);

            } else if (onWatchlist(ipAddressPair) && str.contains("Password:")) {
                // capture the username and start capturing the password
                String username = getCapturedPacketData(ipAddressPair, destinationPort);
                log.trace("Captured username: " + username);
                storeUsername(ipAddressPair, destinationPort, username);
                // clear the captured data
                clearCapturedPacketData(ipAddressPair, destinationPort);

            } else if (onWatchlist(ipAddressPair) && str.contains("Login incorrect")) {
                // the login was a failure, capture username and password
                String password = getCapturedPacketData(ipAddressPair, destinationPort);
                log.trace("Captured password: " + password);
                // get the captured username from telnetLoginsInProgress
                storePassword(ipAddressPair, destinationPort, password, packetInfo.get(PacketInfo.TIMESTAMP));
                // add the failure record for the IpAddressPair in failedAttempts
                moveTelnetLoginAttemptToFailedAttempts(ipAddressPair, destinationPort);
                // clear the packetData
                clearCapturedPacketData(ipAddressPair, destinationPort);

            } else if (onWatchlist(ipAddressPair) && str.contains("Connected to")) {
                // the login was a success, clear the captured data and records
                // clear the watchList, packetData, and telnetLoginsInProgress records
                clearCapturedPacketData(ipAddressPair, destinationPort);
                removeTelnetLoginAttempt(ipAddressPair, destinationPort);
                removeFromWatchList(ipAddressPair);
            }

        } else if (onWatchlist(ipAddressPair) && destinationPort == TELNET_PORT) { // the possible attacker is sending
            // if the IP Address pair in on the watchList, capture the data
            // capture the PacketInfo
            addToWatchList(ipAddressPair, packetInfo);
            // capture the data
            capturePacketData(ipAddressPair, sourcePort, str);

        }

    }
}
