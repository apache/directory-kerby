/*
 * $HeadURL: http://juliusdavies.ca/svn/not-yet-commons-ssl/tags/commons-ssl-0.3.16/src/java/org/apache/commons/ssl/LogWrapper.java $
 * $Revision: 121 $
 * $Date: 2007-11-13 21:26:57 -0800 (Tue, 13 Nov 2007) $
 *
 * ====================================================================
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 * ====================================================================
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Apache Software Foundation.  For more
 * information on the Apache Software Foundation, please see
 * <http://www.apache.org/>.
 *
 */

package org.apache.commons.ssl;

import java.io.BufferedOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;

/**
 * <p/>
 * LogWrapper can be used for situations where log4j might not be available on
 * the classpath.  It presents the most basic and critical components of the
 * log4j API, and passes all log calls through to log4j if possible.  If log4j
 * is not available, logging is sent to standard-out by default.
 * <p/>
 * This default logging to standard-out (which only occurs if log4j is NOT
 * available) can be disabled or changed via the static setBackupStream() and
 * setBackupLogFile() methods.
 *
 * @author Credit Union Central of British Columbia
 * @author <a href="http://www.cucbc.com/">www.cucbc.com</a>
 * @author <a href="mailto:juliusdavies@cucbc.com">juliusdavies@cucbc.com</a>
 * @since 3-Aug-2006
 */
public class LogWrapper {

    // final static String[] LEVELS = {"DEBUG", "INFO", "WARN", "ERROR", "FATAL"};
    final static String[] LEVELS = {"+", " ", "!", "*", "#"};
    final static String TIMESTAMP_PATTERN = "zzz:yyyy-MM-dd/HH:mm:ss.SSS";
    final static int TIMESTAMP_LENGTH = TIMESTAMP_PATTERN.length();
    final static String LINE_SEPARATOR = System.getProperty("line.separator");
    final static DateFormat DF = new SimpleDateFormat(TIMESTAMP_PATTERN);

    private final static LogWrapper NOOP = new LogWrapper();

    /** Should we print DEBUG statements if log4j is not available? */
    private final static boolean DEBUG = true;

    /** true if log4j is available */
    public final static boolean log4j;

    /**
     * OutputStream to log to if log4j is not available.  Set it to null to
     * disable.
     */
    private static volatile OutputStream backup = System.out;

    /** The wrappingPrintStream is lazy-initted if we have to log a stacktrace. */
    private static volatile PrintStream wrappingPrintStream = null;

    private final LogHelper h;

    static {
        boolean avail = false;
        try {
            // LogHelper's constructor will blow up if log4j.jar isn't on the
            // classpath.
            LogHelper lh = new LogHelper(LogWrapper.class);
            lh.hashCode();
            avail = true;
        }
        catch (Throwable t) {
            avail = false;
        }
        finally {
            log4j = avail;
        }
    }

    public static boolean isLog4jAvailable() { return log4j; }

    public static LogWrapper getLogger(Class c) {
        return log4j ? new LogWrapper(c) : NOOP;
    }

    public static LogWrapper getLogger(String s) {
        return log4j ? new LogWrapper(s) : NOOP;
    }

    private LogWrapper() { this.h = null; }

    private LogWrapper(Class c) { this.h = new LogHelper(c); }

    private LogWrapper(String s) { this.h = new LogHelper(s); }

    public void debug(Object o) {
        if (t(0, o, null)) {
            h.debug(o);
        }
    }

    public void debug(Object o, Throwable t) {
        if (t(0, o, t)) {
            h.debug(o, t);
        }
    }

    public void info(Object o) {
        if (t(1, o, null)) {
            h.info(o);
        }
    }

    public void info(Object o, Throwable t) {
        if (t(1, o, t)) {
            h.info(o, t);
        }
    }

    public void warn(Object o) {
        if (t(2, o, null)) {
            h.warn(o);
        }
    }

    public void warn(Object o, Throwable t) {
        if (t(2, o, t)) {
            h.warn(o, t);
        }
    }

    public void error(Object o) {
        if (t(3, o, null)) {
            h.error(o);
        }
    }

    public void error(Object o, Throwable t) {
        if (t(3, o, t)) {
            h.error(o, t);
        }
    }

    public void fatal(Object o) {
        if (t(4, o, null)) {
            h.fatal(o);
        }
    }

    public void fatal(Object o, Throwable t) {
        if (t(4, o, t)) {
            h.fatal(o, t);
        }
    }

    public boolean isDebugEnabled() { return log4j ? h.isDebugEnabled() : DEBUG;}

    public boolean isInfoEnabled() { return !log4j || h.isInfoEnabled(); }

    public Object getLog4jLogger() { return log4j ? h.getLog4jLogger() : null; }


    /**
     * Tests if log4j is available.  If not, logs to backup OutputStream (if
     * backup != null).
     *
     * @param level log4j logging level for this statement
     * @param o     object to log
     * @param t     throwable to log
     * @return true if log4j is available, false if log4j is not.  If it returns
     *         false, as a side-effect, it will also log the statement.
     */
    private boolean t(int level, Object o, Throwable t) {
        if (log4j) {
            return true;
        } else {
            // LogWrapper doesn't log debug statements if Log4j is not available
            // and DEBUG is false.
            if (backup != null && (DEBUG || level > 0)) {
                String s = "";  // log4j allows null
                if (o != null) {
                    try {
                        s = (String) o;
                    }
                    catch (ClassCastException cce) {
                        s = o.toString();
                    }
                }
                int len = s.length() + TIMESTAMP_LENGTH + 9;
                String timestamp = DF.format(new Date());
                StringBuffer buf = new StringBuffer(len);
                buf.append(timestamp);
                if (LEVELS[level].length() == 1) {
                    buf.append(LEVELS[level]);
                } else {
                    buf.append(' ');
                    buf.append(LEVELS[level]);
                    buf.append(' ');
                }
                buf.append(s);
                buf.append(LINE_SEPARATOR);
                s = buf.toString();
                byte[] logBytes = s.getBytes();
                try {
                    if (t == null) {
                        backup.write(logBytes);
                    } else {
                        synchronized (backup) {
                            backup.write(logBytes);
                            if (t != null) {
                                if (wrappingPrintStream == null) {
                                    wrappingPrintStream = new PrintStream(backup, false);
                                }
                                t.printStackTrace(wrappingPrintStream);
                                wrappingPrintStream.flush();
                            }
                        }
                    }
                    backup.flush();   // J2RE 1.5.0 IBM J9 2.3 Linux x86-32 needs this.
                }
                catch (IOException ioe) {
                    throw new RuntimeException(ioe.toString());
                }
            }
            return false;
        }
    }

    /**
     * Set file to log to if log4j is not available.
     *
     * @param f path to use for backup log file (if log4j not available)
     * @throws java.io.IOException if we can't write to the given path
     */
    public static void setBackupLogFile(String f)
        throws IOException {
        if (!log4j) {
            OutputStream out = new FileOutputStream(f, true);
            out = new BufferedOutputStream(out);
            setBackupStream(out);
        }
    }

    /**
     * Set PrintStream to log to if log4j is not available.  Set to null to
     * disable.  Default value is System.out.
     *
     * @param os outputstream to use for backup logging (if log4j not available)
     */
    public static void setBackupStream(OutputStream os) {
        // synchronize on the old backup - don't want to pull the rug out from
        // under him if he's working on a big stacktrace or something like that.
        if (backup != null) {
            synchronized (backup) {
                wrappingPrintStream = null;
                backup = os;
            }
        } else {
            wrappingPrintStream = null;
            backup = os;
        }
    }

    /**
     * Get the PrintStream we're logging to if log4j is not available.
     *
     * @return OutputStream we're using as our log4j replacement.
     */
    public static OutputStream getBackupStream() { return backup; }

}
