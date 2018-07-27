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

import java.io.OutputStream;
import java.io.PrintStream;

/**
 * SystemErrEater
 * <p/>
 * Pcap4j is wonderful, but it uses SLF4J as its logging framework.  This
 * causes a "no configuration" error message to be printed to stderr when
 * Pcap4j is loaded.  This class eats the System.err stream so that the
 * error message is not shown.  This is probably not the best approach to
 * solve this problem, but this project needs to be completed ;)
 */
public class SystemErrEater extends PrintStream {

    private static NullOutputStream nullOutputStream = new NullOutputStream();
    private static SystemErrEater eater = new SystemErrEater(nullOutputStream);

    private SystemErrEater(OutputStream outputStream) {
        super(outputStream);
    }

    public static SystemErrEater getEater() {
        return eater;
    }

}
