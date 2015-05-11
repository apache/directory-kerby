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

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.kerby.kerberos.kerb.client.KrbClient;
import org.apache.kerby.kerberos.kerb.client.KrbConfig;
import org.apache.kerby.kerberos.kerb.client.KrbConfigKey;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.ServerSocket;

public abstract class KdcTestBase {
    protected static final String TEST_PASSWORD = "123456";
    private static File TEST_DIR;

    protected String kdcRealm;
    protected String clientPrincipal;
    protected String serverPrincipal;

    protected String hostname = "localhost";
    protected int tcpPort = -1;
    protected int udpPort = -1;

    protected TestKdcServer kdcServer;
    protected KrbClient krbClnt;

    /**
     * Get a server socket point for testing usage, either TCP or UDP.
     * @return server socket point
     */
    private static int getServerPort() {
        int serverPort = 0;

        try {
            ServerSocket serverSocket = new ServerSocket(0);
            serverPort = serverSocket.getLocalPort();
            serverSocket.close();
        } catch (IOException e) {
            throw new RuntimeException("Failed to get a server socket point");
        }

        return serverPort;
    }

    @BeforeClass
    public static void createTestDir() throws IOException {
        String basedir = System.getProperty("basedir");
        if (basedir == null) {
            basedir = new File(".").getCanonicalPath();
        }
        File targetdir= new File(basedir, "target");
        TEST_DIR = new File(targetdir, "tmp");
        TEST_DIR.mkdirs();
    }

    @AfterClass
    public static void deleteTestDir() throws IOException {
        FileUtils.deleteDirectory(TEST_DIR);
    }

    protected boolean allowUdp() {
        return true;
    }

    protected boolean allowTcp() {
        return true;
    }

    public String getFileContent(String path) throws IOException {
        FileInputStream inputStream = new FileInputStream(path);
        String content = IOUtils.toString(inputStream, "UTF-8");
        inputStream.close();
        return content;
    }

    public String writeToTestDir(String content, String fileName) throws IOException {
        File file = new File(TEST_DIR, fileName);
        if (file.exists()) {
            file.delete();
        }
        FileOutputStream outputStream = new FileOutputStream(file);
        IOUtils.write(content, outputStream, "UTF-8");
        outputStream.close();
        return file.getPath();
    }

    @Before
    public void setUp() throws Exception {

        if (allowTcp()) {
            tcpPort = getServerPort();
        }

        if (allowUdp()) {
            udpPort = getServerPort();
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
        if (useEventModelClient()) {
            krbClnt.useEventModel();
        }
    }

    /**
     * Prepare KDC startup options and config.
     * @throws Exception
     */
    protected void prepareKdcServer() throws Exception {
        kdcServer.setKdcHost(hostname);
        kdcServer.setAllowTcp(allowTcp());
        if (tcpPort > 0) {
            kdcServer.setKdcTcpPort(tcpPort);
        }

        kdcServer.setAllowUdp(allowUdp());
        if (udpPort > 0) {
            kdcServer.setKdcUdpPort(udpPort);
        }

        if (useEventModelKdc()) {
            kdcServer.useEventModel();
        }
    }

    protected boolean useEventModelKdc() {
        return false;
    }

    protected boolean useEventModelClient() {
        return false;
    }

    protected void setUpKdcServer() throws Exception {
        kdcServer = new TestKdcServer();
        prepareKdcServer();
        kdcServer.init();

        kdcRealm = kdcServer.getKdcRealm();
        clientPrincipal = "drankye@" + kdcRealm;
        serverPrincipal = "test-service/localhost@" + kdcRealm;
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

        krbClnt.setTimeout(50);
        krbClnt.setKdcRealm(kdcServer.getKdcRealm());
    }

    protected void createPrincipals() {
        kdcServer.createTgsPrincipal();
        kdcServer.createPrincipals(serverPrincipal);
    }

    protected void deletePrincipals() {
        kdcServer.deleteTgsPrincipal();
        kdcServer.deletePrincipals(serverPrincipal);
    }

    @After
    public void tearDown() throws Exception {
        deletePrincipals();
        kdcServer.stop();
    }
}