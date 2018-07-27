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

package com.liquid.packetanalyzer.arp;

import com.liquid.packetanalyzer.main.Main;
import org.apache.logging.log4j.core.Logger;

import java.util.HashMap;

/**
 * IpMacTracker
 * <p/>
 * IP Address-to-MAC Address and MAC Address-to-IP Address tracking
 * based on ARP traffic.  Each mapping obtained from ARP increases the
 * confidence counter.  This is used to detect spoofed IP packets.
 */
public class IpMacTracker {
    private static Logger log = Main.log;

    private final HashMap<String, IpMacAddressPair> pairMap = new HashMap<>();

    public IpMacTracker() {
    }

    public IpMacTrackerResult query(String ipAddress, String macAddress) {
        IpMacAddressPair ipPair = pairMap.get(ipAddress);
        IpMacAddressPair macPair = pairMap.get(macAddress);
        if ((ipPair == null) && (macPair == null)) {
            // neither address found => create a new entry
            IpMacAddressPair newEntry = new IpMacAddressPair(ipAddress, macAddress);
            pairMap.put(ipAddress, newEntry);
            pairMap.put(macAddress, newEntry);
            log.trace("Creating new IP Address / MAC Address pair: " + newEntry);
            return IpMacTrackerResult.NEW_ENTRY;
        } else if (ipPair == null) {
            // MAC address pair was found, but nothing was found for the IP address => likely spoofing of a bogus IP address
            log.trace("*** Possible Spoofing!! IP Address NOT FOUND, MAC Address pair: " + macPair);
            log.info("*** Possible Spoofing!  Source IP Address " + ipAddress + " may be fake!");
            return IpMacTrackerResult.POSSIBLE_SPOOFING_FAKE_IP_ADDRESS;
        } else if (macPair == null) {
            // IP address pair was found, but nothing found for the MAC address => possible MAC address spoofing?
            log.trace("*** Possible Spoofing!! IP Address pair: " + ipPair + ", MAC Address NOT FOUND");
            log.info("*** Possible Spoofing!  MAC Address " + macAddress + " may be fake!");
            return IpMacTrackerResult.POSSIBLE_SPOOFING_FAKE_MAC_ADDRESS;
        } else if (!ipPair.equals(macPair)) {
            // both addresses found, but they do not match => likely spoofing of a node
            // this could be due to a DHCP server reusing an IP address, but it seems unlikely
            // for this school assignment.  If necessary, add DHCP processor to augment the ARP
            // processing that we use for the IpMacTracker
            log.trace("*** Possible Spoofing!! IP Address pair: " + ipPair + ", MAC Address pair: " + macPair);
            log.info("*** Possible Spoofing!  Source IP Address " + ipAddress + " may not be true sender!");
            return IpMacTrackerResult.POSSIBLE_SPOOFING_IMPERSONATING_IP_ADDRESS;
        } else if (ipPair.equals(macPair)) {
            // both addresses found and they match => existing entry found
            ipPair.incrementConfidenceCount();
            log.trace("Found existing IP Address / MAC Address pair: " + ipPair);
            return IpMacTrackerResult.EXISTING_ENTRY;
        } else { // should not reach here
            throw new IllegalStateException("query failure!  ipPair: " + ipPair + ", macPair: " + macPair);
        }
    }

    public IpMacAddressPair get(String address) {
        return pairMap.get(address);
    }

}
