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
package org.apache.kerby.kerberos.kerb.server;

import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.client.KrbClient;
import org.apache.kerby.kerberos.kerb.client.KrbConfig;
import org.apache.kerby.kerberos.kerb.client.KrbConfigKey;
import org.apache.kerby.util.IOUtil;
import org.apache.kerby.util.NetworkUtil;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;

import java.io.File;
import java.io.IOException;

public abstract class KdcTestBase {
    private static File testDir;

    private final String kdcRealm = "TEST.COM";
    protected final String clientPassword = "123456";
    private final String hostname = "localhost";
    private final String clientPrincipalName = "drankye";
    private final String clientPrincipal = clientPrincipalName + "@" + kdcRealm;
    private final String serverPrincipalName = "test-service";
    private final String serverPrincipal =
            serverPrincipalName + "/" + hostname + "@" + kdcRealm;

    private int tcpPort = -1;
    private int udpPort = -1;

    protected SimpleKdcServer kdcServer;
    protected KrbClient krbClnt;

    @BeforeClass
    public static void createTestDir() throws IOException {
        String basedir = System.getProperty("basedir");
        if (basedir == null) {
            basedir = new File(".").getCanonicalPath();
        }
        File targetdir= new File(basedir, "target");
        testDir = new File(targetdir, "tmp");
        testDir.mkdirs();
    }

    @AfterClass
    public static void deleteTestDir() throws IOException {
        testDir.delete();
    }

    public File getTestDir() {
        return testDir;
    }

    protected String getClientPrincipalName() {
        return clientPrincipalName;
    }

    protected String getClientPrincipal() {
        return clientPrincipal;
    }

    protected String getServerPrincipalName() {
        return serverPrincipalName;
    }

    protected String getClientPassword() {
        return clientPassword;
    }

    protected String getServerPrincipal() {
        return serverPrincipal;
    }

    protected boolean allowUdp() {
        return true;
    }

    protected boolean allowTcp() {
        return true;
    }

    protected int getTcpPort() {
        return tcpPort;
    }

    protected int getUdpPort() {
        return udpPort;
    }

    protected String getFileContent(String path) throws IOException {
        return IOUtil.readFile(new File(path));
    }

    protected String writeToTestDir(String content,
                                    String fileName) throws IOException {
        File file = new File(testDir, fileName);
        if (file.exists()) {
            file.delete();
        }
        IOUtil.writeFile(content, file);
        return file.getPath();
    }

    @Before
    public void setUp() throws Exception {
        if (allowTcp()) {
            tcpPort = NetworkUtil.getServerPort();
        }

        if (allowUdp()) {
            udpPort = NetworkUtil.getServerPort();
        }

        setUpKdcServer();

        setUpClient();
        createPrincipals();
    }

    /**
     * Prepare KrbClient startup options and config.
     * @throws Exception
     */
    protected void prepareKrbClient() throws Exception {

    }

    /**
     * Prepare KDC startup options and config.
     * @throws Exception
     */
    protected void prepareKdcServer() throws Exception {
        kdcServer.setKdcRealm(kdcRealm);
        kdcServer.setKdcHost(hostname);
        kdcServer.setAllowTcp(allowTcp());
        if (tcpPort > 0) {
            kdcServer.setKdcTcpPort(tcpPort);
        }

        kdcServer.setAllowUdp(allowUdp());
        if (udpPort > 0) {
            kdcServer.setKdcUdpPort(udpPort);
        }
    }

    protected void setUpKdcServer() throws Exception {
        kdcServer = new SimpleKdcServer();
        prepareKdcServer();
        kdcServer.init();
    }

    protected void setUpClient() throws Exception {
        KrbConfig krbConfig = new KrbConfig();
        krbConfig.setString(KrbConfigKey.PERMITTED_ENCTYPES,
            "aes128-cts-hmac-sha1-96 des-cbc-crc des-cbc-md5 des3-cbc-sha1");

        krbClnt = new KrbClient(krbConfig);
        prepareKrbClient();

        krbClnt.setKdcHost(hostname);
        krbClnt.setAllowTcp(allowTcp());
        if (tcpPort > 0) {
            krbClnt.setKdcTcpPort(tcpPort);
        }
        krbClnt.setAllowUdp(allowUdp());
        if (udpPort > 0) {
            krbClnt.setKdcUdpPort(udpPort);
        }

        krbClnt.setTimeout(1000);
        krbClnt.setKdcRealm(kdcServer.getKdcRealm());
    }

    protected void createPrincipals() throws KrbException {
        kdcServer.createTgsPrincipal();
        kdcServer.createPrincipals(serverPrincipal);
        kdcServer.createPrincipal(clientPrincipal, clientPassword);
    }

    protected void deletePrincipals() throws KrbException {
        kdcServer.deleteTgsPrincipal();
        kdcServer.deletePrincipals(serverPrincipal);
        kdcServer.deletePrincipal(clientPrincipal);
    }

    @After
    public void tearDown() throws Exception {
        deletePrincipals();
        kdcServer.stop();
    }
}