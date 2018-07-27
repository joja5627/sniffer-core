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

import org.junit.Assert;
import org.junit.Test;

/**
 * IpAddressPairTest
 * <p/>
 * Tests for IpAddressPair
 */
public class IpAddressPairTest {

    private static final String addr1 = "205.251.242.103:443";
    private static final String addr2 = "176.32.98.155:22";
    private static final IpAddressPair p1 = new IpAddressPair(addr1, addr2);
    private static final IpAddressPair p2 = new IpAddressPair(addr2, addr1);

    @Test
    public void hashCodeTest() {
        int h1 = p1.hashCode();
        int h2 = p2.hashCode();
        System.out.println("p1 hashCode is: " + h1);
        System.out.println("p2 hashCode is: " + h2);
        Assert.assertEquals(h1, h2);
    }

    @Test
    public void equalsTest() {
        Assert.assertTrue(p1.equals(p2));
        Assert.assertTrue(p2.equals(p1));
    }
}
