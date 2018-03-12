/**
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 *
 */
package org.apache.kerby.has.server;

import org.apache.hadoop.http.HttpConfig;
import org.apache.kerby.has.common.HasConfig;
import org.apache.kerby.has.common.HasException;
import org.apache.kerby.has.common.util.HasUtil;
import org.apache.kerby.has.server.web.WebConfigKey;
import org.apache.kerby.has.server.web.WebServer;
import org.apache.kerby.kerberos.kdc.impl.NettyKdcServerImpl;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.admin.kadmin.local.LocalKadmin;
import org.apache.kerby.kerberos.kerb.admin.kadmin.local.LocalKadminImpl;
import org.apache.kerby.kerberos.kerb.client.ClientUtil;
import org.apache.kerby.kerberos.kerb.client.KrbConfig;
import org.apache.kerby.kerberos.kerb.client.KrbSetting;
import org.apache.kerby.kerberos.kerb.identity.backend.IdentityBackend;
import org.apache.kerby.kerberos.kerb.server.KdcServer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;

/**
 * The HAS KDC server implementation.
 */
public class HasServer {
    public static final Logger LOG = LoggerFactory.getLogger(HasServer.class);

    private static HasServer server = null;

    private KrbSetting krbSetting;
    private KdcServer kdcServer;
    private WebServer webServer;
    private File confDir;
    private File workDir;
    private String kdcHost;
    private HasConfig hasConfig;

    public HasServer(File confDir) throws KrbException {
        this.confDir = confDir;
    }

    private void setConfDir(File confDir) {
        this.confDir = confDir;
    }

    public File getConfDir() {
        return confDir;
    }

    public File getWorkDir() {
        return workDir;
    }

    public void setWorkDir(File workDir) {
        this.workDir = workDir;
    }

    public void setKdcHost(String host) {
        this.kdcHost = host;
    }

    public String getKdcHost() {
        return kdcHost;
    }

    public KrbSetting getKrbSetting() {
        return krbSetting;
    }

    public KdcServer getKdcServer() {
        return kdcServer;
    }

    public WebServer getWebServer() {
        return webServer;
    }

    public void setWebServer(WebServer webServer) {
        this.webServer = webServer;
    }

    public void startKdcServer() throws HasException {
        try {
            kdcServer = new KdcServer(confDir);
        } catch (KrbException e) {
            throw new HasException("Failed to create KdcServer. " + e.getMessage());
        }
        kdcServer.setWorkDir(workDir);
        kdcServer.setInnerKdcImpl(new NettyKdcServerImpl(kdcServer.getKdcSetting()));
        try {
            kdcServer.init();
        } catch (KrbException e) {
            LOG.error("Errors occurred when init has kdc server:  " + e.getMessage());
            throw new HasException("Errors occurred when init has kdc server:  " + e.getMessage());
        }

        KrbConfig krbConfig;
        try {
            krbConfig = ClientUtil.getConfig(confDir);
        } catch (KrbException e) {
            throw new HasException("Errors occurred when getting the config from conf dir. "
                + e.getMessage());
        }
        if (krbConfig == null) {
            krbConfig = new KrbConfig();
        }
        this.krbSetting = new KrbSetting(krbConfig);
        try {
            kdcServer.start();
        } catch (KrbException e) {
            throw new HasException("Failed to start kdc server. " + e.getMessage());
        }
        try {
            HasUtil.setEnableConf(new File(confDir, "has-server.conf"), "false");
        } catch (Exception e) {
            throw new HasException("Failed to enable conf. " + e.getMessage());
        }
        setHttpFilter();
    }

    public File initKdcServer() throws KrbException {
        File adminKeytabFile = new File(workDir, "admin.keytab");
        if (kdcServer == null) {
            throw new KrbException("Please start KDC server first.");
        }
        LocalKadmin kadmin = new LocalKadminImpl(kdcServer.getKdcSetting(),
            kdcServer.getIdentityService());
        if (adminKeytabFile.exists()) {
            throw new KrbException("KDC Server is already inited.");
        }
        kadmin.createBuiltinPrincipals();
        kadmin.exportKeytab(adminKeytabFile, kadmin.getKadminPrincipal());
        System.out.println("The keytab for kadmin principal "
            + " has been exported to the specified file "
            + adminKeytabFile.getAbsolutePath() + ", please safely keep it, "
            + "in order to use kadmin tool later");

        return adminKeytabFile;
    }

    private void setHttpFilter() throws HasException {
        File httpKeytabFile = new File(workDir, "http.keytab");
        LocalKadmin kadmin = new LocalKadminImpl(kdcServer.getKdcSetting(),
            kdcServer.getIdentityService());
        createHttpPrincipal(kadmin);
        try {
            kadmin.exportKeytab(httpKeytabFile, getHttpPrincipal());
        } catch (KrbException e) {
            throw new HasException("Failed to export keytab: " + e.getMessage());
        }
        webServer.getConf().setString(WebConfigKey.HAS_AUTHENTICATION_FILTER_AUTH_TYPE,
            hasConfig.getFilterAuthType());
        webServer.getConf().setString(WebConfigKey.HAS_AUTHENTICATION_KERBEROS_PRINCIPAL_KEY,
            getHttpPrincipal());
        webServer.getConf().setString(WebConfigKey.HAS_AUTHENTICATION_KERBEROS_KEYTAB_KEY,
            httpKeytabFile.getPath());
        webServer.defineFilter();
    }

    public void createHttpPrincipal(LocalKadmin kadmin) throws HasException {
        String httpPrincipal = getHttpPrincipal();
        IdentityBackend backend = kdcServer.getIdentityService();
        try {
            if (backend.getIdentity(httpPrincipal) == null) {
                kadmin.addPrincipal(httpPrincipal);
            } else {
                LOG.info("The http principal already exists in backend.");
            }
        } catch (KrbException e) {
            throw new HasException("Failed to add principal, " + e.getMessage());
        }
    }

    public String getHttpPrincipal() throws HasException {
        String realm = kdcServer.getKdcSetting().getKdcRealm();
        String nameString;
        try {
            InetAddress addr = InetAddress.getLocalHost();
            String fqName = addr.getCanonicalHostName();
            nameString = "HTTP/" + fqName + "@" + realm;
        } catch (UnknownHostException e) {
            throw new HasException(e);
        }
        LOG.info("The http principal name is: " + nameString);
        return nameString;
    }

    public void stopKdcServer() {
        try {
            kdcServer.stop();
        } catch (KrbException e) {
            LOG.error("Fail to stop has kdc server");
        }
    }

    public void startWebServer() throws HasException {
        if (webServer == null) {
            HasConfig conf = new HasConfig();

            // Parse has-server.conf to get http_host and http_port
            File confFile = new File(confDir, "has-server.conf");
            hasConfig = HasUtil.getHasConfig(confFile);
            try {
                String httpHost;
                String httpPort;
                String httpsHost;
                String httpsPort;
                if (hasConfig.getHttpHost() != null) {
                    httpHost = hasConfig.getHttpHost();
                } else {
                    LOG.info("Cannot get the http_host from has-server.conf, using the default http host.");
                    httpHost = WebConfigKey.HAS_HTTP_HOST_DEFAULT;
                }
                if (hasConfig.getHttpPort() != null) {
                    httpPort = hasConfig.getHttpPort();
                } else {
                    LOG.info("Cannot get the http_port from has-server.conf, using the default http port.");
                    httpPort = String.valueOf(WebConfigKey.HAS_HTTP_PORT_DEFAULT);
                }
                if (hasConfig.getHttpsHost() != null) {
                    httpsHost = hasConfig.getHttpsHost();
                } else {
                    LOG.info("Cannot get the https_host from has-server.conf, using the default https host.");
                    httpsHost = WebConfigKey.HAS_HTTPS_HOST_DEFAULT;
                }
                if (hasConfig.getHttpsPort() != null) {
                    httpsPort = hasConfig.getHttpsPort();
                } else {
                    LOG.info("Cannot get the https_port from has-server.conf , using the default https port.");
                    httpsPort = String.valueOf(WebConfigKey.HAS_HTTPS_PORT_DEFAULT);
                }
                String hasHttpAddress = httpHost + ":" + httpPort;
                String hasHttpsAddress = httpsHost + ":" + httpsPort;
                LOG.info("The web server http address: " + hasHttpAddress);
                LOG.info("The web server https address: " + hasHttpsAddress);

                conf.setString(WebConfigKey.HAS_HTTP_ADDRESS_KEY, hasHttpAddress);
                conf.setString(WebConfigKey.HAS_HTTPS_ADDRESS_KEY, hasHttpsAddress);
                conf.setString(WebConfigKey.HAS_HTTP_POLICY_KEY,
                    HttpConfig.Policy.HTTP_AND_HTTPS.name());
                conf.setString(WebConfigKey.HAS_SERVER_HTTPS_KEYSTORE_RESOURCE_KEY,
                    hasConfig.getSslServerConf());
                webServer = new WebServer(conf);
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException("https_port should be a number. "
                    + e.getMessage());
            }
        } else {
            hasConfig = webServer.getConf();
        }
        webServer.start();
        webServer.defineConfFilter();
        try {
            HasUtil.setEnableConf(new File(confDir, "has-server.conf"), "true");
        } catch (IOException e) {
            throw new HasException("Errors occurred when enable conf. " + e.getMessage());
        }
        webServer.setWebServerAttribute(this);
    }

    public void stopWebServer() {
        if (webServer != null) {
            try {
                webServer.stop();
            } catch (Exception e) {
                LOG.error("Failed to stop http server. " + e.getMessage());
            }
        }
    }

    public static void main(String[] args) {
        if (args[0].equals("-start")) {
            String confDirPath = args[1];
            String workDirPath = args[2];
            File confDir = new File(confDirPath);
            if (!confDir.exists()) {
                System.err.println("The conf-dir is invalid or does not exist");
                System.exit(3);
            }
            File workDir = new File(workDirPath);
            if (!workDir.exists()) {
                System.err.println("The work-dir is invalid or does not exist");
                System.exit(3);
            }

            try {
                server = new HasServer(confDir);
            } catch (KrbException e) {
                LOG.error("Errors occurred when create kdc server:  " + e.getMessage());
                System.exit(4);
            }
            server.setConfDir(confDir);
            server.setWorkDir(workDir);
            //Only start the webserver, the kdcserver could be started after setting the realm
            try {
                server.startWebServer();
            } catch (HasException e) {
                LOG.error("Errors occurred when start has http server:  " + e.getMessage());
                System.exit(6);
            }

            if (server.getWebServer().getHttpAddress() != null) {
                LOG.info("HAS http server started.");
                LOG.info("host: " + server.getWebServer().getHttpAddress().getHostName());
                LOG.info("port: " + server.getWebServer().getHttpAddress().getPort());
            }
            if (server.getWebServer().getHttpsAddress() != null) {
                LOG.info("HAS https server started.");
                LOG.info("host: " + server.getWebServer().getHttpsAddress().getHostName());
                LOG.info("port: " + server.getWebServer().getHttpsAddress().getPort());
            }
        } else if (args[0].equals("-stop")) {
            if (server != null) {
                server.stopWebServer();
                server.stopKdcServer();
            }
        } else {
            System.exit(2);
        }
    }
}
