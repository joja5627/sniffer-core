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

/**
 * IpMacAddressPair
 * <p/>
 * Represents a pair of IP and MAC addresses that are being tracked
 */
public class IpMacAddressPair {

    public final String ipAddress;
    public final String macAddress;
    private long confidenceCount = 1;

    public IpMacAddressPair(String ipAddress, String macAddress) {
        if ((ipAddress == null) || (macAddress == null) || (ipAddress.isEmpty()) || (macAddress.isEmpty())) {
            throw new IllegalArgumentException("IpMacAddressPair addresses cannot be null or empty!");
        }
        this.ipAddress = ipAddress;
        this.macAddress = macAddress;
    }

    public long getConfidenceCount() {
        return confidenceCount;
    }

    public void incrementConfidenceCount() {
        this.confidenceCount++;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        IpMacAddressPair that = (IpMacAddressPair) o;
        return ipAddress.equals(that.ipAddress) && macAddress.equals(that.macAddress);
    }

    @Override
    public int hashCode() {
        int result = ipAddress.hashCode();
        result = 31 * result + macAddress.hashCode();
        return result;
    }

    @Override
    public String toString() {
        return "IpMacAddressPair{" +
                "ipAddress='" + ipAddress + '\'' +
                ", macAddress='" + macAddress + '\'' +
                ", confidenceCount=" + confidenceCount +
                '}';
    }
}
