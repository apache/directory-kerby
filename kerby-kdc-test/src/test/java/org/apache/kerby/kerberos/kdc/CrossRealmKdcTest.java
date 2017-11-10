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
package org.apache.kerby.kerberos.kdc;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.File;
import java.io.IOException;
import java.net.InetAddress;
import java.net.URL;
import java.net.UnknownHostException;

import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.client.KrbClient;
import org.apache.kerby.kerberos.kerb.client.KrbConfig;
import org.apache.kerby.kerberos.kerb.server.SimpleKdcServer;
import org.apache.kerby.kerberos.kerb.server.TestKdcServer;
import org.apache.kerby.kerberos.kerb.type.ticket.SgtTicket;
import org.apache.kerby.kerberos.kerb.type.ticket.TgtTicket;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * A test for a cross-realm KDC call.
 */
public class CrossRealmKdcTest {

    private static final String REALM1 = "TEST.COM";
    private static final String REALM2 = "TEST2.COM";

    private static File testDir1;
    private static File testDir2;

    private KerbyCrossRealmKdc kdc1;
    private KerbyCrossRealmKdc kdc2;

    @BeforeClass
    public static void createTestDirs() throws IOException {
        String basedir = System.getProperty("basedir");
        if (basedir == null) {
            basedir = new File(".").getCanonicalPath();
        }
        File targetdir = new File(basedir, "target");

        testDir1 = new File(targetdir, "tmp1");
        testDir1.mkdirs();

        testDir2 = new File(targetdir, "tmp2");
        testDir2.mkdirs();
    }

    @AfterClass
    public static void deleteTestDir() throws IOException {
        testDir1.delete();
        testDir2.delete();
    }

    public CrossRealmKdcTest() throws Exception {
        // Create the two KDCs
        URL krb5FileUrl = this.getClass().getResource("/realm1/krb5-cross-realm.conf");
        kdc1 = startKdc(krb5FileUrl, REALM1, testDir1);

        URL krb5FileUrl2 = this.getClass().getResource("/realm2/krb5-cross-realm2.conf");
        kdc2 = startKdc(krb5FileUrl2, REALM2, testDir2);
    }

    private KerbyCrossRealmKdc startKdc(URL krb5FileURL, String realm, File workDir) throws Exception {
        File krb5File = new File(krb5FileURL.toURI());
        KrbConfig krbConfig = new KrbConfig();
        krbConfig.addKrb5Config(krb5File);
        SimpleKdcServer kdcServer = new TestKdcServer(krb5File.getParentFile(), krbConfig);

        KerbyCrossRealmKdc kdc = new KerbyCrossRealmKdc(realm);
        kdc.setKdcServer(kdcServer);
        kdc.configKdcServerAndClient(workDir);
        kdc.prepareKdc();

        kdcServer.start();

        kdc.createPrincipals();

        return kdc;
    }

    @Test
    public void testCrossRealm() throws Exception {
        TgtTicket tgt;
        SgtTicket tkt;

        try {
            tgt = kdc1.getKrbClient().requestTgt(
                kdc1.getClientPrincipal(), kdc1.getClientPassword());
            assertThat(tgt).isNotNull();

            tkt = kdc1.getKrbClient().requestSgt(tgt, kdc2.getServerPrincipal());
            assertThat(tkt).isNotNull();
        } catch (Exception e) {
            Assert.fail("Exception occurred with good password. "
                    + e.toString());
        }
    }

    private static class KerbyCrossRealmKdc {

        private final String clientPassword = "123456";
        private String hostname;
        private final String clientPrincipalName = "drankye";
        private final String serverPassword = "654321";
        private final String serverPrincipalName = "test-service";

        private SimpleKdcServer kdcServer;
        private String realm;

        KerbyCrossRealmKdc(String realm) {
            this.realm = realm;
            try {
                hostname = InetAddress.getByName("127.0.0.1").getHostName();
            } catch (UnknownHostException e) {
                hostname = "localhost";
            }
        }

        public void prepareKdc() throws KrbException {
            kdcServer.init();
        }

        public String getClientPassword() {
            return clientPassword;
        }

        public void createPrincipals() throws KrbException {
            kdcServer.createPrincipal(getServerPrincipal(), serverPassword);
            kdcServer.createPrincipal(getClientPrincipal(), clientPassword);

            // Special cross-realm principal
            kdcServer.createPrincipal("krbtgt/TEST2.COM@TEST.COM", "security");
        }

        public void setKdcServer(SimpleKdcServer kdcServer) {
            this.kdcServer = kdcServer;
        }

        public void configKdcServerAndClient(File workDir) {
            kdcServer.setWorkDir(workDir);
        }

        public KrbClient getKrbClient() {
            return kdcServer.getKrbClient();
        }

        public String getClientPrincipal() {
            return clientPrincipalName + "@" + realm;
        }

        public String getServerPrincipal() {
            return serverPrincipalName + "/" + hostname + "@" + realm;
        }
    }
}
