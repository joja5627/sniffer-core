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

import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;

/**
 * CommandLineOptions
 * <p/>
 * Define and parse command line arguments
 */
public class CommandLineOptions {

    public static final String CLI_NAME = "lfpa";
    public static final String MODE = "mode";
    public static final String OUTPUT_FILE = "output-file";
    public static final String INPUT_FILES = "input-files";
    public static final String SILENT = "silent";
    public static final String VERBOSE = "verbose";
    public static final String HELP = "help";

    private static final Options options = new Options();
    private static final HelpFormatter helpFormatter = new HelpFormatter();
    private static final int width = 100;
    private static final String header = "";
    private static final String footer = "Example:  " + CLI_NAME + " -m 1 -f capture.tcpdump";

    static {
        Option mode = Option.builder("m")
                .longOpt(MODE)
                .hasArg()
                .argName("MODE")
                .type(Integer.class)
                .desc("Analysis mode to use.  Three modes are supported:\n" +
                        "=== Mode 1:  Basic Analysis: ===\n" +
                        "* Count of unique IP addresses\n" +
                        "* Count of TCP handshakes\n" +
                        "* Count of UDP sources\n" +
                        "* Count of Non-IP packets\n" +
                        "=== Mode 2:  Detailed Analysis: ===\n" +
                        "* Count of unique IP addresses\n" +
                        "* Count of TCP handshakes\n" +
                        "* Count of UDP sources\n" +
                        "* Count of Non-IP packets\n" +
                        "* TCP Flow Details:\n" +
                        "* * Source / Destination IP pairs\n" +
                        "* * SEQ and ACK numbers at each step of the handshake\n" +
                        "* * Total bytes in Flow (based on FIN flags)\n" +
                        "* Count of packets for all protocols observed for IP packets\n" +
                        "=== Mode 3:  Possible Attacks Analysis: ===\n" +
                        "Identify the following types of attacks:\n" +
                        "* Account hacking (guessing passwords)\n" +
                        "* Port / IP scanning\n" +
                        "* SYN flood\n" +
                        "* Ping of death\n" +
                        "* Smurf attack\n" +
                        "* If one of the above possible attacks is\n" +
                        "* detected the following details are reported:\n" +
                        "* * Name of attack\n" +
                        "* * Source IP and port of attack\n" +
                        "* * Attack target(s) IP and ports\n" +
                        "* * Time first seen\n" +
                        "* * Duration of attack\n" +
                        "* * Usernames and passwords if applicable\n"
                ).build();
        options.addOption(mode);

        Option outputFile = Option.builder("o")
                .longOpt(OUTPUT_FILE)
                .hasArg()
                .argName("OUTPUT_FILE")
                .type(String.class)
                .desc("Write output to the specified output file")
                .build();
        options.addOption(outputFile);

        Option inputFiles = Option.builder("f")
                .longOpt(INPUT_FILES)
                .hasArgs()
                .argName("INPUT_FILES")
                .desc("Input files in tcpdump / pcap format")
                .build();
        options.addOption(inputFiles);

        Option silent = Option.builder("s")
                .longOpt(SILENT)
                .desc("Do not print output to the console")
                .build();
        options.addOption(silent);

        Option verbose = Option.builder("v")
                .longOpt(VERBOSE)
                .desc("Generate verbose output")
                .build();
        options.addOption(verbose);

        Option help = Option.builder("h")
                .longOpt(HELP)
                .desc("Print help and usage instructions")
                .build();
        options.addOption(help);
    }

    public static Options getCommandLineOptions() {
        return options;
    }

    public static void printHelp() {
        System.out.println("Liquid Fortress Packet Analyzer");
        helpFormatter.printHelp(width, CLI_NAME, header, options, footer);
    }
}
