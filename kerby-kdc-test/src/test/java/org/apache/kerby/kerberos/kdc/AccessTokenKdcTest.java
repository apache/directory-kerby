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

import java.io.InputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;

import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.client.KrbTokenClient;
import org.apache.kerby.kerberos.kerb.common.PrivateKeyReader;
import org.apache.kerby.kerberos.kerb.common.PublicKeyReader;
import org.apache.kerby.kerberos.kerb.server.TestKdcServer;
import org.apache.kerby.kerberos.kerb.type.ticket.SgtTicket;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class AccessTokenKdcTest extends TokenKdcTestBase {

    @Test
    public void testRequestServiceTicketWithAccessToken() throws Exception {
        prepareToken(getServerPrincipal());
        performTest();
    }

    @Test
    public void testBadIssuer() throws Exception {
        PrivateKey privateKey;
        try (InputStream is = TokenKdcTestBase.class.getResourceAsStream("/private_key.pem");) {
            privateKey = PrivateKeyReader.loadPrivateKey(is);
        }

        prepareToken(getServerPrincipal(), "oauth1.com", privateKey, null);
        
        try {
            performTest();
            Assertions.fail("Failure expected on a bad issuer value");
        } catch (Exception ex) {
            // expected
            Assertions.assertTrue(ex instanceof KrbException);
        }
    }

    @Test
    public void testBadAudienceRestriction() throws Exception {
        PrivateKey privateKey;
        try (InputStream is = TokenKdcTestBase.class.getResourceAsStream("/private_key.pem");) {
            privateKey = PrivateKeyReader.loadPrivateKey(is);
        }

        prepareToken("bad-service" + "/" + getHostname() + "@" + TestKdcServer.KDC_REALM,
                ISSUER, privateKey, null);
        
        try {
            performTest();
            Assertions.fail("Failure expected on a bad audience restriction value");
        } catch (Exception ex) {
            // expected
            Assertions.assertTrue(ex instanceof KrbException);
        }
    }

    @Test
    public void testUnsignedToken() throws Exception {
        prepareToken(getServerPrincipal(), ISSUER, null, null);
        
        try {
            performTest();
            Assertions.fail("Failure expected on an unsigned token");
        } catch (Exception ex) {
            // expected
            Assertions.assertTrue(ex instanceof KrbException);
        }
    }
    
    @Test
    public void testSignedTokenWithABadKey() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();
        prepareToken(getServerPrincipal(), ISSUER, keyPair.getPrivate(), null);
        
        try {
            performTest();
            Assertions.fail("Failure expected on a bad key");
        } catch (Exception ex) {
            // expected
            Assertions.assertTrue(ex instanceof KrbException);
        }
    }
    
    @Test
    public void testSignedEncryptedToken() throws Exception {
        PrivateKey privateKey;
        try (InputStream is = TokenKdcTestBase.class.getResourceAsStream("/private_key.pem");) {
            privateKey = PrivateKeyReader.loadPrivateKey(is);
        }
        PublicKey publicKey;
        try (InputStream is = TokenKdcTestBase.class.getResourceAsStream("/oauth2.com_public_key.pem")) {
            publicKey = PublicKeyReader.loadPublicKey(is);
        }
        
        prepareToken(getServerPrincipal(), ISSUER, privateKey, publicKey);
        
        performTest();
    }
    
    @Test
    public void testSignedEncryptedTokenBadSigningKey() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();

        PublicKey publicKey;
        try (InputStream is = TokenKdcTestBase.class.getResourceAsStream("/oauth2.com_public_key.pem")) {
            publicKey = PublicKeyReader.loadPublicKey(is);
        }

        prepareToken(getServerPrincipal(), ISSUER, keyPair.getPrivate(), publicKey);
        
        try {
            performTest();
            Assertions.fail("Failure expected on a bad key");
        } catch (Exception ex) {
            // expected
            Assertions.assertTrue(ex instanceof KrbException);
        }
    }
    
    private void performTest() throws Exception {
        createCredentialCache(getClientPrincipal(), getClientPassword());

        KrbTokenClient tokenClient = getTokenClient();
        try {
            SgtTicket sgtTicket = tokenClient.requestSgt(
                getKrbToken(), getServerPrincipal(), getcCacheFile().getPath());
            verifyTicket(sgtTicket);
        } finally {
            deleteCcacheFile();
        }
    }
}
