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

import com.liquid.packetanalyzer.arp.IpMacTracker;
import com.liquid.packetanalyzer.icmp.PingOfDeathDetector;
import com.liquid.packetanalyzer.icmp.SmurfDetector;
import com.liquid.packetanalyzer.ip.IpDefragmenter;
import com.liquid.packetanalyzer.statistics.IpProtocolCounter;
import com.liquid.packetanalyzer.statistics.UdpSources;
import com.liquid.packetanalyzer.statistics.UniqueIpAddresses;
import com.liquid.packetanalyzer.tcp.AccountBruteForceDetector;
import com.liquid.packetanalyzer.tcp.ActiveTcpConnections;
import com.liquid.packetanalyzer.tcp.ClosedTcpConnections;
import com.liquid.packetanalyzer.tcp.SynFloodDetector;

import java.util.LinkedList;

/**
 * PcapFileSummary
 * <p/>
 * Results from processing a pcap file
 */
public class PcapFileSummary {

    public long packetCount = 0;
    public long nonIpPacketCount = 0;
    public long tcpConnectionCount = 0;
    public final UniqueIpAddresses uniqueIpAddresses = new UniqueIpAddresses();
    public final UdpSources udpSources = new UdpSources();
    public final ActiveTcpConnections activeTcpConnections = new ActiveTcpConnections();
    public final ClosedTcpConnections closedTcpConnections = new ClosedTcpConnections();
    public final IpProtocolCounter ipProtocolCounter = new IpProtocolCounter();
    public final IpMacTracker ipMacTracker = new IpMacTracker();
    public final IpDefragmenter ipDefragmenter = new IpDefragmenter();
    public final PortScanDetector portScanDetector = new PortScanDetector();
    public final PingOfDeathDetector pingOfDeathDetector = new PingOfDeathDetector();
    public final SmurfDetector smurfDetector = new SmurfDetector();
    public final SynFloodDetector synFloodDetector = new SynFloodDetector();
    public final AccountBruteForceDetector accountBruteForceDetector = new AccountBruteForceDetector();
    public final LinkedList<AttackSummary> attackSummaries = new LinkedList<>();

}
