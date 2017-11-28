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

import org.apache.commons.dbutils.DbUtils;
import org.apache.kerby.has.common.HasConfig;
import org.apache.kerby.has.common.HasException;
import org.apache.kerby.has.common.util.HasUtil;
import org.apache.kerby.has.server.web.WebConfigKey;
import org.apache.kerby.has.server.web.WebServer;
import org.apache.hadoop.http.HttpConfig;
import org.apache.kerby.kerberos.kdc.impl.NettyKdcServerImpl;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.admin.kadmin.local.LocalKadmin;
import org.apache.kerby.kerberos.kerb.admin.kadmin.local.LocalKadminImpl;
import org.apache.kerby.kerberos.kerb.client.ClientUtil;
import org.apache.kerby.kerberos.kerb.client.KrbConfig;
import org.apache.kerby.kerberos.kerb.client.KrbSetting;
import org.apache.kerby.kerberos.kerb.identity.backend.BackendConfig;
import org.apache.kerby.kerberos.kerb.identity.backend.IdentityBackend;
import org.apache.kerby.kerberos.kerb.server.KdcServer;
import org.apache.kerby.kerberos.kerb.server.KdcUtil;
import org.apache.kerby.util.IOUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

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
        BackendConfig backendConfig;
        try {
            backendConfig = KdcUtil.getBackendConfig(getConfDir());
        } catch (KrbException e) {
            throw new HasException("Failed to get backend config. " + e);
        }
        String backendJar = backendConfig.getString("kdc_identity_backend");
        if (backendJar.equals("org.apache.kerby.has.server.kdc.MySQLIdentityBackend")) {
            updateKdcConf();
        }
        try {
            kdcServer = new KdcServer(confDir);
        } catch (KrbException e) {
            throw new HasException("Failed to create KdcServer. " + e);
        }
        kdcServer.setWorkDir(workDir);
        kdcServer.setInnerKdcImpl(new NettyKdcServerImpl(kdcServer.getKdcSetting()));
        try {
            kdcServer.init();
        } catch (KrbException e) {
            LOG.error("Errors occurred when init has kdc server:  " + e.getMessage());
            throw new HasException("Errors occurred when init has kdc server:  " + e.getMessage());
        }

        KrbConfig krbConfig = null;
        try {
            krbConfig = ClientUtil.getConfig(confDir);
        } catch (KrbException e) {
            new HasException("Errors occurred when getting the config from conf dir. "
                + e.getMessage());
        }
        if (krbConfig == null) {
            krbConfig = new KrbConfig();
        }
        this.krbSetting = new KrbSetting(krbConfig);
        try {
            kdcServer.start();
        } catch (KrbException e) {
            throw new HasException("Failed to start kdc server. " + e);
        }
        try {
            HasUtil.setEnableConf(new File(confDir, "has-server.conf"), "false");
        } catch (Exception e) {
            throw new HasException("Failed to enable conf. " + e);
        }
        setHttpFilter();
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

    public File initKdcServer() throws KrbException {
        File adminKeytabFile = new File(workDir, "admin.keytab");
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
            throw new HasException("Failed to add princial, " + e.getMessage());
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

    /**
     * Update conf file.
     *
     * @param confName  conf file name
     * @param values    customized values
     * @throws IOException throw IOException
     * @throws KrbException e
     */
    public void updateConfFile(String confName, Map<String, String> values)
        throws IOException, HasException {
        File confFile = new File(getConfDir().getAbsolutePath(), confName);
        if (confFile.exists()) {
            // Update conf file content
            InputStream templateResource;
            if (confName.equals("has-server.conf")) {
                templateResource = new FileInputStream(confFile);
            } else {
                String resourcePath = "/" + confName + ".template";
                templateResource = getClass().getResourceAsStream(resourcePath);
            }
            String content = IOUtil.readInput(templateResource);
            for (Map.Entry<String, String> entry : values.entrySet()) {
                content = content.replaceAll(Pattern.quote(entry.getKey()), entry.getValue());
            }

            // Delete the original conf file
            boolean delete = confFile.delete();
            if (!delete) {
                throw new HasException("Failed to delete conf file: " + confName);
            }

            // Save the updated conf file
            IOUtil.writeFile(content, confFile);
        } else {
            throw new HasException("Conf file: " + confName + " not found.");
        }
    }

    /**
     * Get KDC Config from MySQL.
     *
     * @return Kdc config
     * @throws KrbException e
     */
    private Map<String, String> getKdcConf() throws HasException {
        PreparedStatement preStm = null;
        ResultSet result = null;
        Map<String, String> kdcConf = new HashMap<>();
        BackendConfig backendConfig;
        try {
            backendConfig = KdcUtil.getBackendConfig(getConfDir());
        } catch (KrbException e) {
            throw new HasException("Getting backend config failed." + e.getMessage());
        }
        String driver = backendConfig.getString("mysql_driver");
        String url = backendConfig.getString("mysql_url");
        String user = backendConfig.getString("mysql_user");
        String password = backendConfig.getString("mysql_password");
        Connection connection = startConnection(driver, url, user, password);
        try {

            // Get Kdc configuration from kdc_config table
            String stmKdc = "SELECT * FROM `kdc_config` WHERE id = 1";
            preStm = connection.prepareStatement(stmKdc);
            result = preStm.executeQuery();
            while (result.next()) {
                String realm = result.getString("realm");
                String servers = result.getString("servers");
                String port = String.valueOf(result.getInt("port"));
                kdcConf.put("servers", servers);
                kdcConf.put("_PORT_", port);
                kdcConf.put("_REALM_", realm);
            }

        } catch (SQLException e) {
            LOG.error("Error occurred while getting kdc config.");
            throw new HasException("Failed to get kdc config. ", e);
        } finally {
            DbUtils.closeQuietly(preStm);
            DbUtils.closeQuietly(result);
            DbUtils.closeQuietly(connection);
        }

        return kdcConf;
    }

    /**
     * Update KDC conf file.
     *
     * @throws KrbException e
     */
    private void updateKdcConf() throws HasException {
        try {
            Map<String, String> values = getKdcConf();
            String host = getKdcHost();
            if (host == null) {
                host = getWebServer().getBindAddress().getHostName();
            }
            values.remove("servers");
            values.put("_HOST_", host);
            updateConfFile("kdc.conf", values);
        } catch (IOException e) {
            throw new HasException("Failed to update kdc config. ", e);
        }
    }

    /**
     * Start the MySQL connection.
     *
     * @param url url of connection
     * @param user username of connection
     * @param password password of connection
     * @throws KrbException e
     * @return MySQL JDBC connection
     */
    private Connection startConnection(String driver, String url, String user,
                                       String password) throws HasException {
        Connection connection;
        try {
            Class.forName(driver);
            connection = DriverManager.getConnection(url, user, password);
            if (!connection.isClosed()) {
                LOG.info("Succeeded in connecting to MySQL.");
            }
        } catch (ClassNotFoundException e) {
            throw new HasException("JDBC Driver Class not found. ", e);
        } catch (SQLException e) {
            throw new HasException("Failed to connecting to MySQL. ", e);
        }

        return connection;
    }

    /**
     * Config HAS server KDC which have MySQL backend.
     * @param backendConfig MySQL backend config
     * @param realm KDC realm to set
     * @param host KDC host to set
     * @param hasServer has server to get param
     * @throws HasException e
     */
    public void configMySQLKdc(BackendConfig backendConfig, String realm, int port,
                               String host, HasServer hasServer) throws HasException {

        // Start mysql connection
        String driver = backendConfig.getString("mysql_driver");
        String url = backendConfig.getString("mysql_url");
        String user = backendConfig.getString("mysql_user");
        String password = backendConfig.getString("mysql_password");
        Connection connection = startConnection(driver, url, user, password);

        ResultSet resConfig = null;
        PreparedStatement preStm = null;
        try {
            createKdcTable(connection); // Create kdc_config table if not exists
            String stm = "SELECT * FROM `kdc_config` WHERE id = 1";
            preStm = connection.prepareStatement(stm);
            resConfig = preStm.executeQuery();
            if (!resConfig.next()) {
                addKdcConfig(connection, realm, port, host);
            } else {
                String oldHost = hasServer.getKdcHost();
                String servers = resConfig.getString("servers");
                String[] serverArray = servers.split(",");
                List<String> serverList = new ArrayList<>();
                Collections.addAll(serverList, serverArray);
                if (serverList.contains(oldHost)) {
                    servers = servers.replaceAll(oldHost, host);
                } else {
                    servers = servers + "," + host;
                }
                boolean initialized = resConfig.getBoolean("initialized");
                updateKdcConfig(connection, initialized, port, realm, servers);
            }
            hasServer.setKdcHost(host);
        } catch (SQLException e) {
            throw new HasException("Failed to config HAS KDC. ", e);
        } finally {
            DbUtils.closeQuietly(preStm);
            DbUtils.closeQuietly(resConfig);
            DbUtils.closeQuietly(connection);
        }
    }

    /**
     * Create kdc_config table in database.
     * @param conn database connection
     * @throws KrbException e
     */
    private void createKdcTable(final Connection conn) throws HasException {
        PreparedStatement preStm = null;
        try {
            String stm = "CREATE TABLE IF NOT EXISTS `kdc_config` ("
                + "port INTEGER DEFAULT 88, servers VARCHAR(255) NOT NULL, "
                + "initialized bool DEFAULT FALSE, realm VARCHAR(255) "
                + "DEFAULT NULL, id INTEGER DEFAULT 1, CHECK (id=1), PRIMARY KEY (id)) "
                + "ENGINE=INNODB;";
            preStm = conn.prepareStatement(stm);
            preStm.executeUpdate();
        } catch (SQLException e) {
            throw new HasException("Failed to create kdc_config table. ", e);
        } finally {
            DbUtils.closeQuietly(preStm);
        }
    }

    /**
     * Add KDC Config information in database.
     * @param conn database connection
     * @param realm realm to add
     * @param port port to add
     * @param host host to add
     */
    private void addKdcConfig(Connection conn, String realm, int port, String host)
        throws HasException {
        PreparedStatement preStm = null;
        try {
            String stm = "INSERT INTO `kdc_config` (port, servers, realm)" + " VALUES(?, ?, ?)";
            preStm = conn.prepareStatement(stm);
            preStm.setInt(1, port);
            preStm.setString(2, host);
            preStm.setString(3, realm);
            preStm.executeUpdate();
        } catch (SQLException e) {
            throw new HasException("Failed to insert into kdc_config table. ", e);
        } finally {
            DbUtils.closeQuietly(preStm);
        }
    }

    /**
     * Update KDC Config record in database.
     * @param conn database connection
     * @param realm realm to update
     * @param port port to update
     * @param servers servers to update
     * @param initialized initial state of KDC Config
     */
    private void updateKdcConfig(Connection conn, boolean initialized, int port,
                                 String realm, String servers) throws HasException {
        PreparedStatement preStm = null;
        try {
            if (initialized) {
                String stmUpdate = "UPDATE `kdc_config` SET servers = ? WHERE id = 1";
                preStm = conn.prepareStatement(stmUpdate);
                preStm.setString(1, servers);
                preStm.executeUpdate();
            } else {
                String stmUpdate = "UPDATE `kdc_config` SET port = ?, realm = ?, servers = ? WHERE id = 1";
                preStm = conn.prepareStatement(stmUpdate);
                preStm.setInt(1, port);
                preStm.setString(2, realm);
                preStm.setString(3, servers);
                preStm.executeUpdate();
            }
        } catch (SQLException e) {
            throw new HasException("Failed to update KDC Config. ", e);
        } finally {
            DbUtils.closeQuietly(preStm);
        }
    }

    /**
     * Read in krb5-template.conf and substitute in the correct port.
     *
     * @return krb5 conf file
     * @throws IOException e
     * @throws KrbException e
     */
    public File generateKrb5Conf() throws HasException {
        Map<String, String> kdcConf = getKdcConf();
        String[] servers = kdcConf.get("servers").split(",");
        int kdcPort = Integer.parseInt(kdcConf.get("_PORT_"));
        String kdcRealm = kdcConf.get("_REALM_");
        StringBuilder kdcBuilder = new StringBuilder();
        for (String server : servers) {
            String append = "\t\tkdc = " + server.trim() + ":" + kdcPort + "\n";
            kdcBuilder.append(append);
        }
        String kdc = kdcBuilder.toString();
        kdc = kdc.substring(0, kdc.length() - 1);
        String resourcePath = "/krb5.conf.template";
        InputStream templateResource = getClass().getResourceAsStream(resourcePath);
        String content = null;
        try {
            content = IOUtil.readInput(templateResource);
        } catch (IOException e) {
            throw new HasException("Read template resource failed. " + e);
        }
        content = content.replaceAll("_REALM_", kdcRealm);
        content = content.replaceAll("_PORT_", String.valueOf(kdcPort));
        content = content.replaceAll("_UDP_LIMIT_", "4096");
        content = content.replaceAll("_KDCS_", kdc);
        File confFile = new File(confDir, "krb5.conf");
        if (confFile.exists()) {
            boolean delete = confFile.delete();
            if (!delete) {
                throw new HasException("File delete error!");
            }
        }
        try {
            IOUtil.writeFile(content, confFile);
        } catch (IOException e) {
            throw new HasException("Write content to conf file failed. " + e);
        }

        return confFile;
    }

    /**
     * Read in has-server.conf and create has-client.conf.
     *
     * @return has conf file
     * @throws IOException e
     * @throws HasException e
     */
    public File generateHasConf() throws HasException, IOException {
        Map<String, String> kdcConf = getKdcConf();
        String servers = kdcConf.get("servers");
        File confFile = new File(getConfDir().getAbsolutePath(), "has-server.conf");
        HasConfig hasConfig = HasUtil.getHasConfig(confFile);
        if (hasConfig != null) {
            String defaultValue = hasConfig.getHttpsHost();
            InputStream templateResource = new FileInputStream(confFile);
            String content = IOUtil.readInput(templateResource);
            content = content.replaceFirst(Pattern.quote(defaultValue), servers);
            File hasFile = new File(confDir, "has-client.conf");
            IOUtil.writeFile(content, hasFile);
            return hasFile;
        } else {
            throw new HasException("has-server.conf not found. ");
        }
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
            if (hasConfig != null) {
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
                throw new HasException("has-server.conf not found in " + confDir + ". ");
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
            File workDir = new File(workDirPath);
            if (!confDir.exists() || !workDir.exists()) {
                LOG.error("Invalid or not exist conf-dir or work-dir");
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
            //Only start the webserver, the kdcserver can start after setting the realm
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
