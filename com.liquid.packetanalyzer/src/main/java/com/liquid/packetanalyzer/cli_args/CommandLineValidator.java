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
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.ParseException;

import java.io.File;
import java.util.LinkedList;

/**
 * CommandLineValidator
 * <p/>
 * Get and validate command line arguments
 */
public class CommandLineValidator {

    private static final CommandLineParser commandLineParser = new DefaultParser();

    private static boolean isModeValid(CommandLine commandLine, ValidatedArgs validatedArgs) {
        if (commandLine.hasOption(CommandLineOptions.MODE)) {
            int mode = Integer.valueOf(commandLine.getOptionValue(CommandLineOptions.MODE));
            switch (mode) {
                case 1:
                    validatedArgs.mode = Mode.BASIC_ANALYSIS;
                    break;
                case 2:
                    validatedArgs.mode = Mode.DETAILED_ANALYSIS;
                    break;
                case 3:
                    validatedArgs.mode = Mode.POSSIBLE_ATTACKS_ANALYSIS;
                    break;
                default:
                    return false;
            }
            return true;
        }
        return false;
    }

    private static boolean areInputFilesValid(CommandLine commandLine, ValidatedArgs validatedArgs) {
        validatedArgs.inputFiles = new LinkedList<>();
        if (commandLine.hasOption(CommandLineOptions.INPUT_FILES)) {
            String[] inputFileStrings = commandLine.getOptionValues(CommandLineOptions.INPUT_FILES);
            for (String inputFileStr : inputFileStrings) {
                // TODO: if no path separator is in the inputFile String, assume current directory as path and append it
                File input = new File(inputFileStr);
                if ((!input.exists()) || (!input.canRead())) {
                    System.out.println("Input file: " + inputFileStr + " does not exist or cannot be read!");
                    return false;
                } else {
                    validatedArgs.inputFiles.add(input);
                }
            }
            return true;
        }
        return false;
    }

    private static boolean isOutputFileValid(CommandLine commandLine, ValidatedArgs validatedArgs) {
        String outputFileStr = commandLine.getOptionValue(CommandLineOptions.OUTPUT_FILE);
        // TODO: if no path separator is in the outputFile String, assume current directory as path and append it
        // TODO: make sure the outputFile is not in the input file list
        validatedArgs.outputFile = new File(outputFileStr);
        boolean existsAndWritable = validatedArgs.outputFile.exists() && validatedArgs.outputFile.canWrite();
        boolean doesNotExistButWritablePath = (validatedArgs.outputFile.getParentFile() != null) &&
                (validatedArgs.outputFile.getParentFile().canWrite());
        return (existsAndWritable || doesNotExistButWritablePath);
    }

    public static ValidatedArgs validateCommandLineArgs(String[] args) {
        ValidatedArgs validatedArgs = new ValidatedArgs();
        CommandLine commandLine = null;
        try {
            commandLine = commandLineParser.parse(CommandLineOptions.getCommandLineOptions(), args);
            // help
            if (commandLine.hasOption(CommandLineOptions.HELP)) {
                CommandLineOptions.printHelp();
                System.exit(0);
            }
            // mode
            if (!isModeValid(commandLine, validatedArgs)) {
                System.out.println("Mode is not valid!  It must be 1, 2, or 3.");
                CommandLineOptions.printHelp();
                System.exit(-1);
            }
            // input files
            if (!areInputFilesValid(commandLine, validatedArgs)) {
                CommandLineOptions.printHelp();
                System.exit(-2);
            }
            // output file
            if (commandLine.hasOption(CommandLineOptions.OUTPUT_FILE) && !isOutputFileValid(commandLine, validatedArgs)) {
                CommandLineOptions.printHelp();
                System.exit(-3);
            }
            // silent
            if (commandLine.hasOption(CommandLineOptions.SILENT)) {
                validatedArgs.silent = true;
                if (validatedArgs.outputFile == null) {
                    System.out.println("Silent and no output file means no output will occur.  You must specify an output file with silent!");
                    CommandLineOptions.printHelp();
                    System.exit(-4);
                }
            }
            // verbose
            if (commandLine.hasOption(CommandLineOptions.VERBOSE)) {
                validatedArgs.verbose = true;
            }
        } catch (ParseException e) {
            CommandLineOptions.printHelp();
            System.out.println("The error is:  " + e);
            System.exit(-9);
        }
        return validatedArgs;
    }
}
