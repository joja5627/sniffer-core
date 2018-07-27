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

package com.liquid.packetanalyzer.logging;

import com.liquid.packetanalyzer.cli_args.ValidatedArgs;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.Logger;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.appender.ConsoleAppender;
import org.apache.logging.log4j.core.appender.FileAppender;
import org.apache.logging.log4j.core.config.AppenderRef;
import org.apache.logging.log4j.core.config.Configuration;
import org.apache.logging.log4j.core.config.LoggerConfig;
import org.apache.logging.log4j.core.layout.PatternLayout;


/**
 * LoggerFactory
 * <p/>
 * Get a logger for console and / or file output based on command line args
 */
public class LoggerFactory {

    private static final String CONSOLE_APPENDER = "CONSOLE_APPENDER";
    private static final String FILE_APPENDER = "FILE_APPENDER";
    private static final String LOGGER_NAME = "LFPA_LOGGER";
    private static final Level DEFAULT_LEVEL = Level.INFO;
    private static final Level VERBOSE_LEVEL = Level.TRACE;

    /**
     * Get the logger used for output
     *
     * @param validatedArgs with output file, silent, and verbose options that
     *                      are used to configure the logger
     * @return Logger with dynamically-generated configuration
     */
    public static Logger getLogger(ValidatedArgs validatedArgs) {
        // This approach is ugly, but it circumvents the need for multiple log4j
        // configuration files and simplifies writing results to the console and the output file
        // Silence StatusLogger
        System.setProperty("org.apache.logging.log4j.simplelog.StatusLogger.level", "FATAL");
        // Setup context
        LoggerContext loggerContext = (LoggerContext) LogManager.getContext(false);
        Configuration configuration = loggerContext.getConfiguration();
        // Define layout
        PatternLayout patternLayout = PatternLayout.newBuilder()
                .withConfiguration(configuration)
                // uncomment this pattern for debugging
                //.withPattern("%d{ISO8601} [%level] [%F:%L] %msg%n")
                .build();
        // Add appenders
        AppenderRef[] appenderRefs;
        //// Create console appender unless silent
        ConsoleAppender consoleAppender = null;
        AppenderRef consoleAppenderRef = null;
        if (!validatedArgs.silent) {
            consoleAppender = ConsoleAppender.newBuilder()
                    .setConfiguration(configuration)
                    .withLayout(patternLayout)
                    .withName(CONSOLE_APPENDER)
                    .build();
            consoleAppender.start();
            configuration.addAppender(consoleAppender);
            consoleAppenderRef = AppenderRef.createAppenderRef(CONSOLE_APPENDER, null, null);
        }
        //// Create file appender if output file specified
        FileAppender fileAppender = null;
        AppenderRef fileAppenderRef = null;
        if (validatedArgs.outputFile != null) {
            fileAppender = FileAppender.newBuilder()
                    .setConfiguration(configuration)
                    .withLayout(patternLayout)
                    .withName(FILE_APPENDER)
                    .withFileName(validatedArgs.outputFile.getAbsolutePath())
                    .build();
            fileAppender.start();
            configuration.addAppender(fileAppender);
            fileAppenderRef = AppenderRef.createAppenderRef(FILE_APPENDER, null, null);
        }
        if ((consoleAppenderRef != null) && (fileAppenderRef != null)) {
            appenderRefs = new AppenderRef[]{consoleAppenderRef, fileAppenderRef};
        } else if (consoleAppenderRef != null) {
            appenderRefs = new AppenderRef[]{consoleAppenderRef};
        } else if (fileAppenderRef != null) {
            appenderRefs = new AppenderRef[]{fileAppenderRef};
        } else {
            throw new IllegalStateException("At least one appender must be configured to provide output!");
        }
        // Build and update the LoggerConfig
        Level levelToUse = validatedArgs.verbose ? VERBOSE_LEVEL : DEFAULT_LEVEL;
        LoggerConfig loggerConfig = LoggerConfig.createLogger(false, levelToUse, LOGGER_NAME, "true", appenderRefs, null, configuration, null);
        if (consoleAppender != null) {
            loggerConfig.addAppender(consoleAppender, null, null);
        }
        if (fileAppender != null) {
            loggerConfig.addAppender(fileAppender, null, null);
        }
        configuration.addLogger(LOGGER_NAME, loggerConfig);
        loggerContext.updateLoggers();
        return (Logger) LogManager.getLogger(LOGGER_NAME);
    }

}
