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
package org.apache.kerby.kerberos.kerb.integration.test;

import java.io.InputStream;
import java.security.PrivateKey;
import java.security.PrivilegedAction;
import java.security.Provider;
import java.security.interfaces.RSAPrivateKey;
import java.util.Collections;

import javax.security.auth.Subject;

import org.apache.kerby.kerberos.kerb.KrbRuntime;
import org.apache.kerby.kerberos.kerb.common.PrivateKeyReader;
import org.apache.kerby.kerberos.kerb.gss.KerbyGssProvider;
import org.apache.kerby.kerberos.kerb.integration.test.gss.GssAppClient;
import org.apache.kerby.kerberos.kerb.integration.test.gss.GssAppServer;
import org.apache.kerby.kerberos.kerb.provider.TokenEncoder;
import org.apache.kerby.kerberos.kerb.type.base.AuthToken;
import org.apache.kerby.kerberos.kerb.type.base.KrbToken;
import org.apache.kerby.kerberos.kerb.type.base.TokenFormat;
import org.apache.kerby.kerberos.provider.token.JwtTokenEncoder;
import org.junit.Before;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.junit.Assert.assertTrue;

public class KerbyTokenAppTest extends TokenAppTest {

    private static final Logger LOG = LoggerFactory.getLogger(KerbyGssAppTest.class);

    @Before
    @Override
    public void setUp() throws Exception {
        Provider provider = new KerbyGssProvider();
        java.security.Security.insertProviderAt(provider, 1);
        super.setUp();
    }

    // Here the client is sending a JWT token to the service as an "access token", to be
    // inserted into the AuthorizationData part of the service ticket.
    @Test
    public void testJwtAccessToken() throws Exception {
        runAppClientWithToken(createAppClient());
    }

    private void runAppClientWithToken(final AppClient appClient) throws Exception {
        Subject subject = loginClientUsingPassword();

        // Get an AuthToken
        AuthToken authToken = issueToken(getClientPrincipal());
        authToken.isAcToken(true);
        authToken.isIdToken(false);
        authToken.setAudiences(Collections.singletonList(getServerPrincipal()));
        KrbToken krbToken = new KrbToken(authToken, TokenFormat.JWT);

        // Sign it
        try (InputStream is = this.getClass().getResource("/private_key.pem").openStream()) {
            PrivateKey signKey = PrivateKeyReader.loadPrivateKey(is);
            krbToken.setTokenValue(signToken(authToken, signKey));
        }

        // Add KrbToken to the private creds
        subject.getPrivateCredentials().add(krbToken);

        Subject.doAs(subject, new PrivilegedAction<Object>() {
            @Override
            public Object run() {
                try {
                    appClient.run();
                } catch (Exception ex) {
                    LOG.error(ex.toString());
                }
                return null;
            }
        });

        assertTrue("Client successfully connected and authenticated to server",
                   appClient.isTestOK());
    }

    private byte[] signToken(AuthToken authToken, PrivateKey signKey) throws Exception {
        TokenEncoder tokenEncoder = KrbRuntime.getTokenProvider("JWT").createTokenEncoder();
        assertTrue(tokenEncoder instanceof JwtTokenEncoder);

        ((JwtTokenEncoder) tokenEncoder).setSignKey((RSAPrivateKey) signKey);
        return tokenEncoder.encodeAsBytes(authToken);
    }

    @Override
    protected AppServer createAppServer() throws Exception {
        return new GssAppServer(new String[] {
            String.valueOf(getServerPort()),
            getServerPrincipal()
        });
    }

    private AppClient createAppClient() throws Exception {
        return new GssAppClient(new String[] {
            getHostname(),
            String.valueOf(getServerPort()),
                getClientPrincipal(),
                getServerPrincipal()
        });
    }
}
