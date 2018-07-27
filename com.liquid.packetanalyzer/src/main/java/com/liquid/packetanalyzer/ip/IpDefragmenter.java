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

package com.liquid.packetanalyzer.ip;

import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.util.IpV4Helper;

import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;

/**
 * IpDefragmenter
 * <p/>
 * Tracks and assembles fragmented IP packets
 */
public class IpDefragmenter {

    private final HashMap<Integer, List<IpV4Packet>> fragments = new HashMap<>();

    public IpDefragmenter() {
    }

    public void addFragment(int identification, IpV4Packet fragment) {
        List<IpV4Packet> collected = fragments.get(identification);
        if (collected == null) {
            collected = new LinkedList<IpV4Packet>();
        }
        collected.add(fragment);
        fragments.put(identification, collected);
    }

    public IpV4Packet defragment(int identification) {
        List<IpV4Packet> collected = fragments.get(identification);
        if (collected == null) {
            throw new IllegalArgumentException("No fragments collected for ID: " + identification);
        }
        fragments.remove(identification);
        return IpV4Helper.defragment(collected);
    }
}
