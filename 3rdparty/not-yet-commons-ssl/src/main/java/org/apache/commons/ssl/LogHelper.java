/*
 * $HeadURL: http://juliusdavies.ca/svn/not-yet-commons-ssl/tags/commons-ssl-0.3.16/src/java/org/apache/commons/ssl/LogHelper.java $
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

import org.apache.log4j.Logger;

/**
 * <p/>
 * Wraps a Log4j Logger.  This non-public class is the one actually interacting
 * with the log4j.jar library.  That way LogWrapper can safely attempt to use
 * log4j.jar, but still degrade gracefully and provide logging via standard-out
 * even if log4j is unavailable.
 * <p/>
 * The interactions with log4j.jar could be done directly inside LogWrapper
 * as long as the Java code is compiled by Java 1.4 or greater (still works
 * at runtime in Java 1.3).  The interactions with log4j.jar only need to be
 * pushed out into a separate class like this for people using a Java 1.3
 * compiler, which creates bytecode that is more strict with depedency
 * checking.
 *
 * @author Credit Union Central of British Columbia
 * @author <a href="http://www.cucbc.com/">www.cucbc.com</a>
 * @author <a href="mailto:juliusdavies@cucbc.com">juliusdavies@cucbc.com</a>
 * @since 3-Aug-2006
 */
final class LogHelper {
    private final Logger l;

    LogHelper(Class c) { l = Logger.getLogger(c); }

    LogHelper(String s) { l = Logger.getLogger(s); }

    void debug(Object o) { l.debug(o); }

    void debug(Object o, Throwable t) { l.debug(o, t); }

    void info(Object o) { l.info(o); }

    void info(Object o, Throwable t) { l.info(o, t); }

    void warn(Object o) { l.warn(o); }

    void warn(Object o, Throwable t) { l.warn(o, t); }

    void error(Object o) { l.error(o); }

    void error(Object o, Throwable t) { l.error(o, t); }

    void fatal(Object o) { l.fatal(o); }

    void fatal(Object o, Throwable t) { l.fatal(o, t); }

    boolean isDebugEnabled() { return l.isDebugEnabled(); }

    boolean isInfoEnabled() { return l.isInfoEnabled(); }

    Object getLog4jLogger() { return l; }
}
