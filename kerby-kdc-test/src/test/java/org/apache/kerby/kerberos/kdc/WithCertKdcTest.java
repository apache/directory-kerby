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
import org.apache.kerby.kerberos.kerb.KrbRuntime;
import org.apache.kerby.kerberos.kerb.provider.PkiLoader;
import org.apache.kerby.kerberos.kerb.server.KdcTestBase;
import org.apache.kerby.kerberos.kerb.spec.ticket.ServiceTicket;
import org.apache.kerby.kerberos.kerb.spec.ticket.TgtTicket;
import org.apache.kerby.kerberos.provider.pki.KerbyPkiProvider;
import org.junit.Before;

import java.io.InputStream;
import java.security.PrivateKey;
import java.security.cert.Certificate;

import static org.assertj.core.api.Assertions.assertThat;

/**
 openssl genrsa -out cakey.pem 2048
 openssl req -key cakey.pem -new -x509 -out cacert.pem -days 3650
 vi extensions.kdc
 openssl genrsa -out kdckey.pem 2048
 openssl req -new -out kdc.req -key kdckey.pem
 env REALM=SH.INTEL.COM openssl x509 -req -in kdc.req -CAkey cakey.pem \
 -CA cacert.pem -out kdc.pem -days 365 -extfile extensions.kdc -extensions kdc_cert -CAcreateserial
 */
public class WithCertKdcTest extends KdcTestBase {
    private PkiLoader pkiLoader;

    private Certificate userCert;
    private PrivateKey userKey;

    @Before
    public void setUp() throws Exception {
        KrbRuntime.setPkiProvider(new KerbyPkiProvider());
        pkiLoader = KrbRuntime.getPkiProvider().createPkiLoader();

        super.setUp();
    }

    @Override
    protected void setUpClient() throws Exception {
        super.setUpClient();

        loadCredentials();
    }

    @Override
    protected void prepareKdcServer() throws Exception {
        super.prepareKdcServer();
        kdcServer.createPrincipals(clientPrincipal);
    }

    //@Test
    public void testKdc() throws Exception {
        assertThat(userCert).isNotNull();

        kdcServer.start();
        krbClnt.init();

        TgtTicket tgt = null;
        try {
            tgt = krbClnt.requestTgtWithCert(clientPrincipal, userCert, userKey);
        } catch (KrbException te) {
            assertThat(te.getMessage().contains("timeout")).isTrue();
            return;
        }
        assertThat(tgt).isNull();

        ServiceTicket tkt = krbClnt.requestServiceTicketWithTgt(tgt, serverPrincipal);
        assertThat(tkt).isNull();
    }

    private void loadCredentials() throws KrbException {
        InputStream res = getClass().getResourceAsStream("/usercert.pem");
        userCert = pkiLoader.loadCerts(res).iterator().next();

        res = getClass().getResourceAsStream("/userkey.pem");
        userKey = pkiLoader.loadPrivateKey(res, null);
    }
}