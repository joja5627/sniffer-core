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

import com.liquid.packetanalyzer.main.Mode;

import java.io.File;
import java.util.LinkedList;

/**
 * ValidatedArgs
 * <p/>
 * Container for validated command line args
 */
public class ValidatedArgs {

    public Mode mode;
    public LinkedList<File> inputFiles;
    public File outputFile = null;
    public boolean silent = false;
    public boolean verbose = true;

    @Override
    public String toString() {
        return "ValidatedArgs{" +
                "mode=" + mode +
                ", inputFiles=" + inputFiles +
                ", outputFile=" + outputFile +
                ", silent=" + silent +
                ", verbose=" + verbose +
                '}';
    }
}
