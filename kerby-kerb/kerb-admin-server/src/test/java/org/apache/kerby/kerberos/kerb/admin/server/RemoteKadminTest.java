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
package org.apache.kerby.kerberos.kerb.admin.server;

import org.apache.commons.io.FileUtils;
import org.apache.kerby.kerberos.kerb.admin.AuthUtil;
import org.apache.kerby.kerberos.kerb.admin.kadmin.local.LocalKadminImpl;
import org.apache.kerby.kerberos.kerb.admin.kadmin.remote.AdminClient;
import org.apache.kerby.kerberos.kerb.admin.kadmin.remote.AdminConfig;
import org.apache.kerby.kerberos.kerb.admin.server.kadmin.AdminServer;
import org.apache.kerby.kerberos.kerb.admin.server.kadmin.AdminServerConfig;
import org.apache.kerby.kerberos.kerb.identity.backend.BackendConfig;
import org.apache.kerby.kerberos.kerb.keytab.Keytab;
import org.apache.kerby.kerberos.kerb.request.KrbIdentity;
import org.apache.kerby.kerberos.kerb.server.KdcConfig;
import org.apache.kerby.kerberos.kerb.server.KdcServer;
import org.apache.kerby.kerberos.kerb.server.SimpleKdcServer;
import org.apache.kerby.kerberos.kerb.type.base.PrincipalName;
import org.apache.kerby.util.NetworkUtil;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.Subject;
import javax.security.auth.login.LoginException;
import java.io.File;
import java.util.List;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class RemoteKadminTest {
    private static final Logger LOG = LoggerFactory.getLogger(RemoteKadminTest.class);
    
    protected static File testDir = new File(System.getProperty("test.dir", "target"));
    private static File testClassDir = new File(testDir, "test-classes");
    private static File confDir = new File(testClassDir, "conf");
    private static File workDir = new File(testDir, "work-dir");
    
    private static final String SERVER_HOST = "localhost";

    private static final String ADMIN_PRINCIPAL = "kadmin/EXAMPLE.COM@EXAMPLE.COM";
    private static final String PROTOCOL_PRINCIPAL = "adminprotocol/localhost@EXAMPLE.COM";

    private static KdcServer kdcServer;
    private static LocalKadminImpl localKadmin;
    private static AdminServer adminServer;

    private static SimpleKdcServer buildMiniKdc() throws Exception {
        KdcConfig config = new KdcConfig();
        BackendConfig backendConfig = new BackendConfig();
        backendConfig.addIniConfig(new File(confDir, "backend.conf"));
        SimpleKdcServer kdc = new SimpleKdcServer(config, backendConfig);
        kdc.setWorkDir(workDir);
        
        kdc.setKdcHost(SERVER_HOST);
        int kdcPort = NetworkUtil.getServerPort();
        kdc.setAllowTcp(true);
        kdc.setAllowUdp(false);
        kdc.setKdcTcpPort(kdcPort);
        LOG.info("Starting KDC server at " + SERVER_HOST + ":" + kdcPort);
        kdc.init();
        return kdc;
    }
    
    private static void buildLocalKadmin() throws Exception {
        localKadmin = new LocalKadminImpl(kdcServer.getKdcSetting(), kdcServer.getIdentityService());
        localKadmin.addPrincipal(PROTOCOL_PRINCIPAL);
        localKadmin.exportKeytab(new File(workDir, "protocol.keytab"), PROTOCOL_PRINCIPAL);
        localKadmin.exportKeytab(new File(workDir, "admin.keytab"), ADMIN_PRINCIPAL);
    }
    
    private static AdminServer buildAdminServer() throws Exception {
        AdminServer server = new AdminServer(confDir);
        AdminServerConfig config = server.getAdminServerConfig();
        server.setAdminHost(config.getAdminHost());
        server.setAllowTcp(true);
        server.setAllowUdp(false);
        server.setAdminServerPort(config.getAdminPort());

        server.init();
        return server;
    }

    private AdminClient buildKadminRemoteClient() throws Exception {
        final AdminConfig config = new AdminConfig();
        config.addKrb5Config(new File(confDir, "adminClient.conf"));
        AdminClient adminClient = new AdminClient(config);
        adminClient.setAdminRealm(config.getAdminRealm());
        adminClient.setAllowTcp(true);
        adminClient.setAllowUdp(false);
        adminClient.setAdminTcpPort(config.getAdminPort());

        adminClient.init();
        doSaslHandShake(adminClient, config);
        return adminClient;
    }
    
    @BeforeAll
    public static void setUpBeforeAll() throws Exception {
        workDir.mkdirs();
        
        kdcServer = buildMiniKdc();
        kdcServer.start();

        buildLocalKadmin();
        
        adminServer = buildAdminServer();
        adminServer.start();
    }

    @AfterAll
    public static void tearDownAfterAll() throws Exception {
        adminServer.stop();
        kdcServer.stop();
        FileUtils.deleteDirectory(workDir);
    }

    @Test
    public void remoteListPrincipalTest() throws Exception {
        AdminClient adminClient = buildKadminRemoteClient();
        List<String> principals = adminClient.requestGetprincs();
        assertTrue(principals.contains("kadmin/EXAMPLE.COM@EXAMPLE.COM"));
        assertTrue(principals.contains("krbtgt/EXAMPLE.COM@EXAMPLE.COM"));
        assertTrue(principals.contains("adminprotocol/localhost@EXAMPLE.COM"));

        principals = adminClient.requestGetprincsWithExp("k*");
        assertTrue(principals.contains("kadmin/EXAMPLE.COM@EXAMPLE.COM"));
        assertTrue(principals.contains("krbtgt/EXAMPLE.COM@EXAMPLE.COM"));
        assertFalse(principals.contains("adminprotocol/localhost@EXAMPLE.COM"));
    }

    @Test
    public void remoteModifyPrincipalTest() throws Exception {
        AdminClient adminClient = buildKadminRemoteClient();
        String testPrincipal = "test/EXAMPLE.COM";
        String renamePrincipal = "test_rename/EXAMPLE.COM";
        adminClient.requestAddPrincipal(testPrincipal);
        assertTrue(localKadmin.getPrincipals().contains(testPrincipal + "@EXAMPLE.COM"),
                "Remote kadmin add principal test failed.");

        adminClient.requestRenamePrincipal(testPrincipal, renamePrincipal);
        assertTrue(localKadmin.getPrincipals().contains(renamePrincipal + "@EXAMPLE.COM"),
                "Remote kadmin rename principal test failed, the renamed principal does not exist.");
        assertFalse(localKadmin.getPrincipals().contains(testPrincipal + "@EXAMPLE.COM"),
                "Remote kadmin rename principal test failed, the old principal still exists.");

        adminClient.requestDeletePrincipal(renamePrincipal);
        assertFalse(localKadmin.getPrincipals().contains(renamePrincipal + "@EXAMPLE.COM"),
                "Remote kadmin delete principal test failed.");
    }

    @Test
    public void remoteKtaddTest() throws Exception {
        AdminClient adminClient = buildKadminRemoteClient();
        String testPrincipal = "test/EXAMPLE.COM";
        File keytabOutput = new File(testDir, "test.keytab");
        localKadmin.addPrincipal(testPrincipal);
        adminClient.requestExportKeytab(keytabOutput, testPrincipal);
        Keytab localKeytab = Keytab.loadKeytab(keytabOutput);
        List<String> principalNames = localKeytab.getPrincipals()
                .stream().map(PrincipalName::getName).collect(Collectors.toList());
        assertTrue(principalNames.contains(testPrincipal + "@EXAMPLE.COM"));
    }
    
    @Test
    public void remoteChangePasswordTest() throws Exception {
        AdminClient adminClient = buildKadminRemoteClient();
        String testPrincipal = "cpw/EXAMPLE.COM";
        String oldPassword = "old_pwd";
        String newPassword = "new_pwd";
        localKadmin.addPrincipal(testPrincipal, oldPassword);
        adminClient.requestChangePassword(testPrincipal, newPassword);
        try {
            AuthUtil.loginUsingPassword(testPrincipal, new PasswordCallbackHandler(newPassword));
        } catch (LoginException e) {
            Assertions.fail("Login using new password failed: " + e.toString());
        }
    }
    
    @Test
    public void remoteGetPrincipalTest() throws Exception {
        AdminClient adminClient = buildKadminRemoteClient();
        KrbIdentity identity = adminClient.requestGetPrincipal("kadmin/EXAMPLE.COM");
        KrbIdentity expectIdentity = new KrbIdentity("kadmin/EXAMPLE.COM@EXAMPLE.COM");
        assertEquals(identity, expectIdentity);
    }

    private void doSaslHandShake(AdminClient adminClient, AdminConfig config) throws Exception {
        Subject subject = AuthUtil.loginUsingKeytab(ADMIN_PRINCIPAL, new File(config.getKeyTabFile()));
        adminClient.setSubject(subject);
    }
}
