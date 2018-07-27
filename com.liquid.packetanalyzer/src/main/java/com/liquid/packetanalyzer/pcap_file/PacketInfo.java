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

import java.util.HashMap;
import java.util.Map;

/**
 * PacketInfo
 * <p/>
 * Stores information gathered about the current packet being processed
 */
public class PacketInfo {

    public static final String TIMESTAMP = "TIMESTAMP";
    public static final String SOURCE_MAC = "SOURCE_MAC";
    public static final String DESTINATION_MAC = "DESTINATION_MAC";
    public static final String ETHERTYPE = "ETHERTYPE";
    public static final String SOURCE_ADDRESS = "SOURCE_ADDRESS";
    public static final String SOURCE_PORT = "SOURCE_PORT";
    public static final String DESTINATION_ADDRESS = "DESTINATION_ADDRESS";
    public static final String DESTINATION_PORT = "DESTINATION_PORT";
    public static final String IP_PROTOCOL = "IP_PROTOCOL";
    public static final String IP_IDENTIFICATION = "IP_IDENTIFICATION";
    public static final String WAS_FRAGMENTED = "WAS_FRAGMENTED";
    public static final String SYN = "SYN";
    public static final String ACK = "ACK";
    public static final String FIN = "FIN";

    private final HashMap<String, String> info = new HashMap<>();

    public PacketInfo() {
    }

    public String get(Object o) {
        return info.get(o);
    }

    public boolean containsKey(Object o) {
        return info.containsKey(o);
    }

    public void put(String s, String s2) {
        info.put(s, s2);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        PacketInfo that = (PacketInfo) o;

        return info.equals(that.info);
    }

    @Override
    public int hashCode() {
        return info.hashCode();
    }

    public String toString() {
        StringBuilder builder = new StringBuilder("PacketInfo {\n");
        for (Map.Entry<String, String> entry : info.entrySet()) {
            builder.append(entry.getKey());
            builder.append(" => ");
            builder.append(entry.getValue());
            builder.append("\n");
        }
        builder.append("}");
        return builder.toString();
    }
}
