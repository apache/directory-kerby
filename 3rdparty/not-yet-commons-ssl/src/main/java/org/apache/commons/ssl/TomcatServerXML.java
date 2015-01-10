/*
 * $HeadURL: http://juliusdavies.ca/svn/not-yet-commons-ssl/tags/commons-ssl-0.3.16/src/java/org/apache/commons/ssl/TomcatServerXML.java $
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

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Collections;
import java.util.Map;
import java.util.SortedMap;
import java.util.TreeMap;

/**
 * @author Credit Union Central of British Columbia
 * @author <a href="http://www.cucbc.com/">www.cucbc.com</a>
 * @author <a href="mailto:juliusdavies@cucbc.com">juliusdavies@cucbc.com</a>
 * @since 22-Feb-2007
 */
public class TomcatServerXML {
    private final static LogWrapper log = LogWrapper.getLogger(TomcatServerXML.class);

    /**
     * KeyMaterial extracted from Tomcat's conf/server.xml.  There might be
     * several KeyMaterials to extract if Tomcat has different SSL Certificates
     * listening on different ports.  This particular KeyMaterial will come from
     * the lowest secure port that Tomcat is properly configured to open.
     */
    public final static KeyMaterial KEY_MATERIAL;

    /**
     * TrustMaterial extracted from Tomcat's conf/server.xml.  There might be
     * several TrustMaterials to extract if Tomcat has different SSL Certificates
     * listening on different ports.  This particular TrustMaterial will come
     * from the lowest secure port that Tomcat is properly configured to open.
     * </p><p>
     * There's a good chance this will be set to TrustMaterial.DEFAULT (which
     * use's the JVM's '$JAVA_HOME/jre/lib/security/cacerts' file).
     * </p><p>
     * Note:  With SSLServerSockets, TrustMaterial only matters when the
     * incoming client socket (SSLSocket) presents a client certificate.
     * </p>
     */
    public final static TrustMaterial TRUST_MATERIAL;

    /**
     * new Integer( port ) --> KeyMaterial mapping of SSL Certificates found
     * inside Tomcat's conf/server.xml file.
     */
    public final static SortedMap KEY_MATERIAL_BY_PORT;

    /**
     * new Integer( port ) --> TrustMaterial mapping of SSL configuration
     * found inside Tomcat's conf/server.xml file.
     * </p><p>
     * Many of these will probably be TrustMaterial.DEFAULT (which uses the
     * JVM's '$JAVA_HOME/jre/lib/security/cacerts' file).
     * </p><p>
     * Note:  With SSLServerSockets, TrustMaterial only matters when the
     * incoming client socket (SSLSocket) presents a client certificate.
     * </p>
     */
    public final static SortedMap TRUST_MATERIAL_BY_PORT;

    static {
        String tomcatHome = System.getProperty("catalina.home");
        String serverXML = tomcatHome + "/conf/server.xml";
        TreeMap keyMap = new TreeMap();
        TreeMap trustMap = new TreeMap();
        InputStream in = null;
        Document doc = null;
        try {
            if (tomcatHome != null) {
                File f = new File(serverXML);
                if (f.exists()) {
                    try {
                        in = new FileInputStream(serverXML);
                    }
                    catch (IOException ioe) {
                        // oh well, no soup for us.
                        log.warn("Commons-SSL failed to load Tomcat's [" + serverXML + "] " + ioe);
                    }
                }
            }
            if (in != null) {
                DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
                try {
                    DocumentBuilder db = dbf.newDocumentBuilder();
                    doc = db.parse(in);
                }
                catch (Exception e) {
                    log.warn("Commons-SSL failed to parse Tomcat's [" + serverXML + "] " + e);
                }
            }
            if (doc != null) {
                loadTomcatConfig(doc, keyMap, trustMap);
            }
        }
        finally {
            if (in != null) {
                try { in.close(); } catch (Exception e) { /* . */ }
            }
        }
        KEY_MATERIAL_BY_PORT = Collections.unmodifiableSortedMap(keyMap);
        TRUST_MATERIAL_BY_PORT = Collections.unmodifiableSortedMap(trustMap);

        KeyMaterial km = null;
        TrustMaterial tm = null;
        if (!keyMap.isEmpty()) {
            km = (KeyMaterial) keyMap.get(keyMap.firstKey());
        }
        if (!trustMap.isEmpty()) {
            tm = (TrustMaterial) trustMap.get(trustMap.firstKey());
        }
        KEY_MATERIAL = km;
        TRUST_MATERIAL = tm;

    }

    private static void loadTomcatConfig(Document d, Map keyMap, Map trustMap) {
        final String userHome = System.getProperty("user.home");
        NodeList nl = d.getElementsByTagName("Connector");
        for (int i = 0; i < nl.getLength(); i++) {
            KeyMaterial km = null;
            TrustMaterial tm = null;

            Element element = (Element) nl.item(i);
            String secure = element.getAttribute("secure");
            String portString = element.getAttribute("port");
            Integer port = null;
            String pass;
            try {
                portString = portString != null ? portString.trim() : "";
                port = new Integer(portString);
            }
            catch (NumberFormatException nfe) {
                // oh well
            }
            if (port != null && Util.isYes(secure)) {
                // Key Material
                String keystoreFile = element.getAttribute("keystoreFile");
                pass = element.getAttribute("keystorePass");
                if (!element.hasAttribute("keystoreFile")) {
                    keystoreFile = userHome + "/.keystore";
                }
                if (!element.hasAttribute("keystorePass")) {
                    pass = "changeit";
                }
                char[] keystorePass = pass != null ? pass.toCharArray() : null;

                // Trust Material
                String truststoreFile = element.getAttribute("truststoreFile");
                pass = element.getAttribute("truststorePass");
                if (!element.hasAttribute("truststoreFile")) {
                    truststoreFile = null;
                }
                if (!element.hasAttribute("truststorePass")) {
                    pass = null;
                }
                char[] truststorePass = pass != null ? pass.toCharArray() : null;


                if (keystoreFile == null) {
                    km = null;
                } else {
                    try {
                        km = new KeyMaterial(keystoreFile, keystorePass);
                    }
                    catch (Exception e) {
                        log.warn("Commons-SSL failed to load [" + keystoreFile + "] " + e);
                    }
                }
                if (truststoreFile == null) {
                    tm = TrustMaterial.DEFAULT;
                } else {
                    try {
                        tm = new TrustMaterial(truststoreFile, truststorePass);
                    }
                    catch (Exception e) {
                        log.warn("Commons-SSL failed to load [" + truststoreFile + "] " + e);
                    }
                }

                Object o = keyMap.put(port, km);
                if (o != null) {
                    log.debug("Commons-SSL TomcatServerXML keyMap clobbered port: " + port);
                }
                o = trustMap.put(port, tm);
                if (o != null) {
                    log.debug("Commons-SSL TomcatServerXML trustMap clobbered port: " + port);
                }
            }
        }
    }

}
