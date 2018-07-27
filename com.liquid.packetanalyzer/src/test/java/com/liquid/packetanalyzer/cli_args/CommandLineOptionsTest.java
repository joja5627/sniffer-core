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

package com.liquid.packetanalyzer.cli_args;

import org.junit.Test;

/**
 * CommandLineOptionsTest
 * <p/>
 * Tests for CommandLineOptions
 */
public class CommandLineOptionsTest {

    @Test
    public void testOptions() {
//        Options options = CommandLineOptions.getCommandLineOptions();
//        Assert.assertNotNull(options);
    }

    @Test
    public void testHelp() {
        CommandLineOptions.printHelp();
    }
}
