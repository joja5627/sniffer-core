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

package com.liquid.packetanalyzer.statistics;

import org.pcap4j.packet.namednumber.IpNumber;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/**
 * IpProtocolCounter
 * <p/>
 * Count packets for all observed IP protocols
 */
public class IpProtocolCounter {

    private HashMap<IpNumber, Integer> protocolCounts = new HashMap<>();

    public IpProtocolCounter() {
    }

    public void increment(IpNumber ipNumber) {
        Integer count = protocolCounts.get(ipNumber);
        if (count == null) {
            count = new Integer(1);
        } else {
            count++;
        }
        protocolCounts.put(ipNumber, count);
    }

    public Set<Map.Entry<IpNumber, Integer>> entrySet() {
        return protocolCounts.entrySet();
    }

    public String toString() {
        StringBuilder builder = new StringBuilder("=== IP Protocol Counts ===\n");
        for (Map.Entry<IpNumber, Integer> entry : entrySet()) {
            builder.append(entry.getKey());
            builder.append(": ");
            builder.append(entry.getValue());
            builder.append("\n");
        }
        return builder.toString();
    }
}
