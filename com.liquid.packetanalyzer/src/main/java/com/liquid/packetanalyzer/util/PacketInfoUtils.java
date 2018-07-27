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

package com.liquid.packetanalyzer.util;

import com.liquid.packetanalyzer.pcap_file.PacketInfo;

import java.sql.Timestamp;
import java.util.LinkedHashSet;

/**
 * PacketInfoUtils
 * <p/>
 * Utilities for working with PacketInfo containers
 */
public class PacketInfoUtils {

    // get the earliest PacketInfo in the set based on timestamp
    public static PacketInfo getEarliest(LinkedHashSet<PacketInfo> packetInfos) {
        if ((packetInfos == null) || (packetInfos.isEmpty())) {
            throw new IllegalArgumentException("Cannot get earliest of null or empty PacketInfo set!");
        }
        PacketInfo earliest = null;
        Timestamp earliestTimestamp = null;
        for (PacketInfo current : packetInfos) {
            if (earliest == null) {
                earliest = current;
                earliestTimestamp = Timestamp.valueOf(current.get(PacketInfo.TIMESTAMP));
            } else {
                Timestamp currentTimestamp = Timestamp.valueOf(current.get(PacketInfo.TIMESTAMP));
                if (currentTimestamp.before(earliestTimestamp)) {
                    earliest = current;
                    earliestTimestamp = currentTimestamp;
                }
            }
        }
        return earliest;
    }

    // get the latest PacketInfo in the set based on timestamp
    public static PacketInfo getLatest(LinkedHashSet<PacketInfo> packetInfos) {
        if ((packetInfos == null) || (packetInfos.isEmpty())) {
            throw new IllegalArgumentException("Cannot get latest of null or empty PacketInfo set!");
        }
        PacketInfo latest = null;
        Timestamp latestTimestamp = null;
        for (PacketInfo current : packetInfos) {
            if (latest == null) {
                latest = current;
                latestTimestamp = Timestamp.valueOf(current.get(PacketInfo.TIMESTAMP));
            } else {
                Timestamp currentTimestamp = Timestamp.valueOf(current.get(PacketInfo.TIMESTAMP));
                if (currentTimestamp.after(latestTimestamp)) {
                    latest = current;
                    latestTimestamp = currentTimestamp;
                }
            }
        }
        return latest;
    }
}
