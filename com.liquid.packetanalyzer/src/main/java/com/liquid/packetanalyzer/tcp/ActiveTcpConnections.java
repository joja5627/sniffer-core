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

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/**
 * ActiveTcpConnections
 * <p/>
 * Tracks the state of multiple TCP connections
 * until each connection is closed
 */
public class ActiveTcpConnections {

    private HashMap<IpAddressPair, TcpConnectionTracker> connections = new HashMap<>();

    public int size() {
        return connections.size();
    }

    public TcpConnectionTracker get(Object o) {
        return connections.get(o);
    }

    public TcpConnectionTracker put(IpAddressPair ipAddressPair, TcpConnectionTracker tcpConnectionTracker) {
        return connections.put(ipAddressPair, tcpConnectionTracker);
    }

    public Set<IpAddressPair> keySet() {
        return connections.keySet();
    }

    public Collection<TcpConnectionTracker> values() {
        return connections.values();
    }

    public Set<Map.Entry<IpAddressPair, TcpConnectionTracker>> entrySet() {
        return connections.entrySet();
    }

    public TcpConnectionTracker remove(Object o) {
        return connections.remove(o);
    }
}
