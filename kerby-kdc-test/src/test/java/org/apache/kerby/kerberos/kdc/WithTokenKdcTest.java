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
import org.apache.kerby.kerberos.kerb.provider.TokenEncoder;
import org.apache.kerby.kerberos.kerb.server.KdcTestBase;
import org.apache.kerby.kerberos.kerb.spec.ticket.ServiceTicket;
import org.apache.kerby.kerberos.kerb.spec.ticket.TgtTicket;
import org.apache.kerby.kerberos.kerb.spec.base.AuthToken;
import org.apache.kerby.kerberos.provider.token.JwtTokenProvider;
import org.junit.Before;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

public class WithTokenKdcTest extends KdcTestBase {
    static final String SUBJECT = "test-sub";
    static final String AUDIENCE = "krbtgt@EXAMPLE.COM";
    static final String ISSUER = "oauth2.com";
    static final String GROUP = "sales-group";
    static final String ROLE = "ADMIN";

    private TokenEncoder tokenEncoder;

    private AuthToken authToken;

    @Before
    public void setUp() throws Exception {
        KrbRuntime.setTokenProvider(new JwtTokenProvider());
        tokenEncoder = KrbRuntime.getTokenProvider().createTokenEncoder();
        prepareToken();

        super.setUp();
    }

    private void prepareToken() {
        authToken = KrbRuntime.getTokenProvider().createTokenFactory().createToken();

        authToken.setIssuer(ISSUER);
        authToken.setSubject(SUBJECT);

        authToken.addAttribute("group", GROUP);
        authToken.addAttribute("role", ROLE);

        List<String> aud = new ArrayList<String>();
        aud.add(AUDIENCE);
        authToken.setAudiences(aud);

        // Set expiration in 60 minutes
        final Date NOW =  new Date(new Date().getTime() / 1000 * 1000);
        Date exp = new Date(NOW.getTime() + 1000 * 60 * 60);
        authToken.setExpirationTime(exp);

        Date nbf = NOW;
        authToken.setNotBeforeTime(nbf);

        Date iat = NOW;
        authToken.setIssueTime(iat);
    }

    @Override
    protected void setUpKdcServer() throws Exception {
        super.setUpKdcServer();
        kdcServer.createPrincipals(clientPrincipal);
    }

    //@Test
    public void testKdc() throws Exception {
        kdcServer.start();
        assertThat(kdcServer.isStarted()).isTrue();
        krbClnt.init();

        TgtTicket tgt;
        try {
            tgt = krbClnt.requestTgtTicket(clientPrincipal, authToken, null);
        } catch (KrbException te) {
            assertThat(te.getMessage().contains("timeout")).isTrue();
            return;
        }
        assertThat(tgt).isNull();

        ServiceTicket tkt = krbClnt.requestServiceTicket(tgt, serverPrincipal, null);
        assertThat(tkt).isNull();
    }
}