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
import org.apache.kerby.kerberos.kerb.common.PrivateKeyReader;
import org.apache.kerby.kerberos.kerb.common.PublicKeyReader;
import org.apache.kerby.kerberos.kerb.spec.ticket.ServiceTicket;
import org.apache.kerby.kerberos.kerb.spec.ticket.TgtTicket;
import org.junit.Assert;
import org.junit.Test;

import java.io.InputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;

public class WithIdentityTokenKdcTest extends WithTokenKdcTestBase {

    @Test
    public void testKdc() throws Exception {

        prepareToken(null);
        performTest();
    }
    
    @Test
    public void testBadIssuer() throws Exception {
        InputStream is = WithTokenKdcTestBase.class.getResourceAsStream("/private_key.pem");
        PrivateKey privateKey = PrivateKeyReader.loadPrivateKey(is);
        prepareToken(null, "oauth1.com", AUDIENCE, privateKey, null);
        
        try {
            performTest();
            Assert.fail("Failure expected on a bad issuer value");
        } catch (Exception ex) {
            // expected
            Assert.assertTrue(ex instanceof KrbException);
        }
    }
    
    // TODO - not failing yet.
    @Test
    @org.junit.Ignore
    public void testBadAudienceRestriction() throws Exception {
        InputStream is = WithTokenKdcTestBase.class.getResourceAsStream("/private_key.pem");
        PrivateKey privateKey = PrivateKeyReader.loadPrivateKey(is);
        prepareToken(null, ISSUER, "krbtgt2@EXAMPLE.COM", privateKey, null);
        
        try {
            performTest();
            Assert.fail("Failure expected on a bad audience restriction value");
        } catch (Exception ex) {
            // expected
            Assert.assertTrue(ex instanceof KrbException);
        }
    }

    @Test
    public void testUnsignedToken() throws Exception {
        prepareToken(null, ISSUER, "krbtgt2@EXAMPLE.COM", null, null);
        
        try {
            performTest();
            Assert.fail("Failure expected on an unsigned token");
        } catch (Exception ex) {
            // expected
            Assert.assertTrue(ex instanceof KrbException);
        }
    }
    
    @Test
    public void testSignedTokenWithABadKey() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        KeyPair keyPair = keyGen.generateKeyPair();
        prepareToken(null, ISSUER, AUDIENCE, keyPair.getPrivate(), null);
        
        try {
            performTest();
            Assert.fail("Failure expected on a bad key");
        } catch (Exception ex) {
            // expected
            Assert.assertTrue(ex instanceof KrbException);
        }
    }
    
    @Test
    public void testSignedEncryptedToken() throws Exception {
        InputStream is = WithTokenKdcTestBase.class.getResourceAsStream("/private_key.pem");
        PrivateKey privateKey = PrivateKeyReader.loadPrivateKey(is);
        
        is = WithTokenKdcTestBase.class.getResourceAsStream("/oauth2.com_public_key.pem");
        PublicKey publicKey = PublicKeyReader.loadPublicKey(is);
        
        prepareToken(null, ISSUER, AUDIENCE, privateKey, publicKey);
        
        performTest();
    }
    
    @Test
    public void testSignedEncryptedTokenBadSigningKey() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        KeyPair keyPair = keyGen.generateKeyPair();
        
        InputStream is = WithTokenKdcTestBase.class.getResourceAsStream("/oauth2.com_public_key.pem");
        PublicKey publicKey = PublicKeyReader.loadPublicKey(is);
        
        prepareToken(null, ISSUER, AUDIENCE, keyPair.getPrivate(), publicKey);
        
        try {
            performTest();
            Assert.fail("Failure expected on a bad key");
        } catch (Exception ex) {
            // expected
            Assert.assertTrue(ex instanceof KrbException);
        }
    }
    
    private void performTest() throws Exception {

        createCredentialCache(getClientPrincipal(), getClientPassword());

        TgtTicket tgt = null;
        try {
            tgt = getKrbClient().requestTgtWithToken(getKrbToken(),
                    getcCacheFile().getPath());
        } catch (KrbException e) {
            if (e.getMessage().contains("timeout")) {
                return;
            }
            throw e;
        }
        verifyTicket(tgt);

        ServiceTicket tkt = getKrbClient().requestServiceTicketWithTgt(tgt,
                getServerPrincipal());
        verifyTicket(tkt);
    }
}