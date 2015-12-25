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

import org.apache.kerby.kerberos.kerb.KrbConstant;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.client.KrbConfigKey;
import org.apache.kerby.kerberos.kerb.client.KrbPkinitClient;
import org.apache.kerby.kerberos.kerb.server.KdcConfigKey;
import org.apache.kerby.kerberos.kerb.server.KdcTestBase;
import org.apache.kerby.kerberos.kerb.type.ticket.SgtTicket;
import org.apache.kerby.kerberos.kerb.type.ticket.TgtTicket;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class AnonymousPkinitKdcTest extends KdcTestBase {
    private String serverPrincipal;
    private KrbPkinitClient pkinitClient;

    @Before
    public void setUp() throws Exception {
        super.setUp();

        pkinitClient = getPkinitClient();
    }

    @Override
    protected void configKdcSeverAndClient() {
        super.configKdcSeverAndClient();

        String pkinitIdentity = getClass().getResource("/kdccerttest.pem").getPath() + ","
                + getClass().getResource("/kdckey.pem").getPath();
        getKdcServer().getKdcConfig().setString(KdcConfigKey.PKINIT_IDENTITY, pkinitIdentity);

        String pkinitAnchors = getClass().getResource("/cacerttest.pem").getPath();
        getKrbClient().getKrbConfig().setString(KrbConfigKey.PKINIT_ANCHORS, pkinitAnchors);
    }

    @Override
    protected void createPrincipals() throws KrbException {
        super.createPrincipals();
        //Anonymity support is not enabled by default.
        //To enable it, you must create the principal WELLKNOWN/ANONYMOUS
        getKdcServer().createPrincipal(KrbConstant.ANONYMOUS_PRINCIPAL);
    }

    @Test
    public void testAnonymity() throws Exception {
        TgtTicket tgt;

        try {
            tgt = pkinitClient.requestTgt();
        } catch (KrbException te) {
            te.printStackTrace();
            Assert.fail();
            return;
        }
        assertThat(tgt).isNotNull();

        serverPrincipal = getServerPrincipal();
        SgtTicket tkt = pkinitClient.requestSgt(tgt, serverPrincipal);
        assertThat(tkt).isNotNull();
    }
}
