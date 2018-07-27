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

/**
 * IpAddressPair
 * <p/>
 * Represents a pair of IP addresses that are being tracked
 */
public class IpAddressPair {

    public final String addr1;
    public final String addr2;

    public IpAddressPair(String addr1, String addr2) {
        if ((addr1 == null) || (addr2 == null) || (addr1.isEmpty()) || (addr2.isEmpty())) {
            throw new IllegalArgumentException("IpAddressPair addresses cannot be null or empty!");
        }
        this.addr1 = addr1;
        this.addr2 = addr2;
    }

    // equals and hashCode must ensure that even if addr1 and addr2 are
    // swapped, equals will return true and hashCode will give the same value
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        IpAddressPair that = (IpAddressPair) o;

        return (this.addr1.equals(that.addr1) && (this.addr2.equals(that.addr2))) || // same positions
                (this.addr1.equals(that.addr2) && (this.addr2.equals(that.addr1)));   // swapped positions
    }

    @Override
    public int hashCode() {
        return 31 * (addr1.hashCode() + addr2.hashCode());
    }

    @Override
    public String toString() {
        return "IpAddressPair{" +
                "addr1='" + addr1 + '\'' +
                ", addr2='" + addr2 + '\'' +
                '}';
    }
}
