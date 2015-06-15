/*
 * $HeadURL: http://juliusdavies.ca/svn/not-yet-commons-ssl/tags/commons-ssl-0.3.16/src/java/org/apache/commons/ssl/Version.java $
 * $Revision: 130 $
 * $Date: 2007-11-14 19:24:15 -0800 (Wed, 14 Nov 2007) $
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

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Enumeration;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

/**
 * Extracts tagged version from a subversion $HeadURL: http://juliusdavies.ca/svn/not-yet-commons-ssl/tags/commons-ssl-0.3.16/src/java/org/apache/commons/ssl/Version.java $ property, and prints it
 * out nicely on standard out.
 * <p/>
 * e.g. If this version came from /tags/commons-ssl-0_3_9/, then Version.java
 * will print:  "Version: 0.3.9" on standard out.
 *
 * @author Credit Union Central of British Columbia
 * @author <a href="http://www.cucbc.com/">www.cucbc.com</a>
 * @author <a href="mailto:juliusdavies@cucbc.com">juliusdavies@cucbc.com</a>
 * @since 14-Nov-2007
 */
public class Version {
    public static final String HEAD_URL = "$HeadURL: http://juliusdavies.ca/svn/not-yet-commons-ssl/tags/commons-ssl-0.3.16/src/java/org/apache/commons/ssl/Version.java $";
    public static final String VERSION;
    public static final String COMPILE_TIME;

    static {
        // Try to extract a clean version number from svn's HeadURL property:
        String v = "UNKNOWN";
        boolean fromBranch = false;
        int x = HEAD_URL.lastIndexOf("/tags/");
        if (x >= 0) {
            int y = HEAD_URL.indexOf("/", x + "/tags/".length());
            if (y >= 0) {
                v = HEAD_URL.substring(x + "/tags/".length(), y);
            }
            v = v.replace('_', '.');
            v = v.replace('-', '.');
        } else if (HEAD_URL.indexOf("/trunk/") >= 0) {
            v = "trunk";
        } else if (HEAD_URL.indexOf("/branches/") >= 0) {
            fromBranch = true;
            x = HEAD_URL.indexOf("/branches/");
            int y = HEAD_URL.indexOf("/", x + "/branches/".length());
            if (y >= 0) {
                v = HEAD_URL.substring(x + "/branches/".length(), y);
            }
            v = v.replace('_', '.');
            v = v.replace('-', '.');
        }

        String V = v.toUpperCase();
        x = V.indexOf("COMMONS.SSL.");
        if (x >= 0) {
            v = v.substring(x + "commons.ssl.".length());
        }
        VERSION = fromBranch ? "***Branch*** " + v : v;

        // Try to calculate when jar file was compiled:
        String s;
        try {
            s = CompileTime.getCompileTimeString(Version.class);
        }
        catch (NoClassDefFoundError e) {
            s = null;
        }
        COMPILE_TIME = s;
    }

    public static String versionString() {
        String v;
        if (COMPILE_TIME != null) {
            v = CompileTime.formatVersion(VERSION, COMPILE_TIME);
        } else {
            v = VERSION;
        }
        return "Version: " + v;
    }

    public static void main(String[] args) {
        System.out.println(versionString());
    }

    public String toString() {
        return versionString();
    }


    /**
     * Searches through a jar file to the find the most recent timestamp of
     * all the class files.
     */
    private static class CompileTime {
        private final static String PATTERN = ".jar!";
        private final static String PREFIX = "file:";
        private final static String DF_FORMAT = "zzz:yyyy-MM-dd/HH:mm:ss.SSS";
        private final static DateFormat DF = new SimpleDateFormat(DF_FORMAT);

        public static String getCompileTimeString(Class clazz) {
            String s = clazz.getName();
            s = "/" + s.replace('.', '/') + ".class";
            return getCompileTimeString(s);
        }

        private static String getCompileTimeString(String resource) {
            try {
                Date d = getCompileTime(resource);
                synchronized (DF) {
                    return d != null ? DF.format(d) : "[unknown]";
                }
            }
            catch (IOException ioe) {
                return ioe.toString();
            }
        }

        public static Date getCompileTime(String resource) throws IOException {
            URL url = CompileTime.class.getResource(resource);
            if (url != null) {
                String urlString = url.getFile();
                String fileLocation;
                int i = urlString.indexOf(PATTERN);
                if (i > 0) {
                    int x = i + PATTERN.length() - 1;
                    fileLocation = urlString.substring(0, x);
                    if (fileLocation.startsWith(PREFIX)) {
                        fileLocation = fileLocation.substring(PREFIX.length());
                    }
                    JarFile jf = new JarFile(fileLocation);
                    long newestTime = 0;
                    Enumeration entries = jf.entries();
                    jf.close();
                    while (entries.hasMoreElements()) {
                        JarEntry entry = (JarEntry) entries.nextElement();
                        if (entry.getName().endsWith(".class")) {
                            newestTime = Math.max(newestTime, entry.getTime());
                        }
                    }
                    if (newestTime > 0) {
                        return new Date(newestTime);
                    }
                } else {
                    File f = new File(urlString);
                    try {
                        return new Date(f.lastModified());
                    }
                    catch (Exception e) {
                        return null;
                    }
                }
            }
            return null;
        }

        public static String formatVersion(String version, String compileTime) {
            StringBuffer buf = new StringBuffer();
            buf.append(version);
            buf.append("   Compiled: [");
            buf.append(compileTime);
            buf.append("]");
            return buf.toString();
        }

    }

}
