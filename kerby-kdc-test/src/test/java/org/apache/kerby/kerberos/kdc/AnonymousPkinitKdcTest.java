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

import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.server.KdcConfigKey;
import org.apache.kerby.kerberos.kerb.server.KdcTestBase;
import org.junit.Before;

public class AnonymousPkinitKdcTest extends KdcTestBase {

    //private String serverPrincipal;

    @Before
    public void setUp() throws Exception {
        super.setUp();
    }

    @Override
    protected void configKdcSeverAndClient() {
        super.configKdcSeverAndClient();

        String pkinitIdentity = getClass().getResource("/kdccerttest.pem").getPath() + ","
                + getClass().getResource("/kdckey.pem").getPath();
        getKdcServer().getKdcConfig().setString(KdcConfigKey.PKINIT_IDENTITY, pkinitIdentity);
    }

    @Override
    protected void createPrincipals() throws KrbException {
        super.createPrincipals();
        //Anonymity support is not enabled by default.
        //To enable it, you must create the principal WELLKNOWN/ANONYMOUS
        getKdcServer().createPrincipal("WELLKNOWN/ANONYMOUS");
    }

    // TO BE FIXED
    /*
    @Test
    public void testAnonymity() throws Exception {

        getKrbClient().init();

        URL url = getClass().getResource("/cacerttest.pem");
        TgtTicket tgt;
        KrbPkinitClient pkinitClient = new KrbPkinitClient(getKrbClient());
        try {
            tgt = pkinitClient.requestTgt(url.getPath());
        } catch (KrbException te) {
            te.printStackTrace();
            assertThat(te.getMessage().contains("timeout")).isTrue();
            return;
        }
        assertThat(tgt).isNotNull();

        serverPrincipal = getServerPrincipal();
        SgtTicket tkt = getKrbClient().requestSgt(tgt, serverPrincipal);
        assertThat(tkt).isNotNull();
    }*/
}
