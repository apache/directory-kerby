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

import static org.junit.Assert.*;

import java.io.File;
import java.io.InputStream;
import java.nio.file.Files;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.util.Collections;

import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.KrbRuntime;
import org.apache.kerby.kerberos.kerb.ccache.Credential;
import org.apache.kerby.kerberos.kerb.ccache.CredentialCache;
import org.apache.kerby.kerberos.kerb.client.KrbClient;
import org.apache.kerby.kerberos.kerb.client.KrbTokenClient;
import org.apache.kerby.kerberos.kerb.common.EncryptionUtil;
import org.apache.kerby.kerberos.kerb.common.PrivateKeyReader;
import org.apache.kerby.kerberos.kerb.crypto.EncryptionHandler;
import org.apache.kerby.kerberos.kerb.provider.TokenEncoder;
import org.apache.kerby.kerberos.kerb.type.ad.AdToken;
import org.apache.kerby.kerberos.kerb.type.ad.AuthorizationData;
import org.apache.kerby.kerberos.kerb.type.ad.AuthorizationDataEntry;
import org.apache.kerby.kerberos.kerb.type.base.AuthToken;
import org.apache.kerby.kerberos.kerb.type.base.EncryptionKey;
import org.apache.kerby.kerberos.kerb.type.base.KeyUsage;
import org.apache.kerby.kerberos.kerb.type.base.KrbToken;
import org.apache.kerby.kerberos.kerb.type.base.TokenFormat;
import org.apache.kerby.kerberos.kerb.type.ticket.EncTicketPart;
import org.apache.kerby.kerberos.kerb.type.ticket.SgtTicket;
import org.apache.kerby.kerberos.kerb.type.ticket.TgtTicket;
import org.apache.kerby.kerberos.kerb.type.ticket.Ticket;
import org.apache.kerby.kerberos.provider.token.JwtTokenEncoder;

/**
 * Some tests for JWT tokens using the Kerby client API
 */
public class JWTTokenTest extends TokenLoginTestBase {

    @org.junit.Test
    public void accessToken() throws Exception {

        KrbClient client = getKrbClient();

        // Get a TGT
        TgtTicket tgt = client.requestTgt(getClientPrincipal(), getClientPassword());
        assertNotNull(tgt);

        // Write to cache
        Credential credential = new Credential(tgt);
        CredentialCache cCache = new CredentialCache();
        cCache.addCredential(credential);
        cCache.setPrimaryPrincipal(tgt.getClientPrincipal());

        File cCacheFile = File.createTempFile("krb5_" + getClientPrincipal(), "cc");
        cCache.store(cCacheFile);

        KrbTokenClient tokenClient = new KrbTokenClient(client);

        tokenClient.setKdcHost(client.getSetting().getKdcHost());
        tokenClient.setKdcTcpPort(client.getSetting().getKdcTcpPort());

        tokenClient.setKdcRealm(client.getSetting().getKdcRealm());
        tokenClient.init();

        // Create a JWT token
        AuthToken authToken = issueToken(getClientPrincipal());
        authToken.isAcToken(true);
        authToken.isIdToken(false);
        authToken.setAudiences(Collections.singletonList(getServerPrincipal()));
        KrbToken krbToken = new KrbToken(authToken, TokenFormat.JWT);

        InputStream is = Files.newInputStream(getSignKeyFile().toPath());
        PrivateKey signKey = PrivateKeyReader.loadPrivateKey(is);
        krbToken.setTokenValue(signToken(authToken, signKey));

        // Now get a SGT using the JWT
        SgtTicket tkt = tokenClient.requestSgt(krbToken, getServerPrincipal(), cCacheFile.getPath());
        assertTrue(tkt != null);

        // Decrypt the ticket
        Ticket ticket = tkt.getTicket();
        EncryptionKey key = EncryptionHandler.string2Key(getServerPrincipal(), getServerPassword(),
                                                         ticket.getEncryptedEncPart().getEType());

        EncTicketPart encPart =
            EncryptionUtil.unseal(ticket.getEncryptedEncPart(),
                                  key, KeyUsage.KDC_REP_TICKET, EncTicketPart.class);

        // Examine the authorization data
        AuthorizationData authzData = encPart.getAuthorizationData();
        assertEquals(1, authzData.getElements().size());
        AuthorizationDataEntry dataEntry = authzData.getElements().iterator().next();
        AdToken token = dataEntry.getAuthzDataAs(AdToken.class);
        KrbToken decodedKrbToken = token.getToken();
        assertEquals(getClientPrincipal(), decodedKrbToken.getSubject());
        assertEquals(getServerPrincipal(), decodedKrbToken.getAudiences().get(0));

        cCacheFile.delete();
    }

    @org.junit.Test
    public void accessTokenInvalidAudience() throws Exception {

        KrbClient client = getKrbClient();

        // Get a TGT
        TgtTicket tgt = client.requestTgt(getClientPrincipal(), getClientPassword());
        assertNotNull(tgt);

        // Write to cache
        Credential credential = new Credential(tgt);
        CredentialCache cCache = new CredentialCache();
        cCache.addCredential(credential);
        cCache.setPrimaryPrincipal(tgt.getClientPrincipal());

        File cCacheFile = File.createTempFile("krb5_" + getClientPrincipal(), "cc");
        cCache.store(cCacheFile);

        KrbTokenClient tokenClient = new KrbTokenClient(client);

        tokenClient.setKdcHost(client.getSetting().getKdcHost());
        tokenClient.setKdcTcpPort(client.getSetting().getKdcTcpPort());

        tokenClient.setKdcRealm(client.getSetting().getKdcRealm());
        tokenClient.init();

        // Create a JWT token with an invalid audience
        AuthToken authToken = issueToken(getClientPrincipal());
        authToken.isAcToken(true);
        authToken.isIdToken(false);
        authToken.setAudiences(Collections.singletonList(getServerPrincipal() + "_"));
        KrbToken krbToken = new KrbToken(authToken, TokenFormat.JWT);

        InputStream is = Files.newInputStream(getSignKeyFile().toPath());
        PrivateKey signKey = PrivateKeyReader.loadPrivateKey(is);
        krbToken.setTokenValue(signToken(authToken, signKey));

        // Now get a SGT using the JWT
        try {
            tokenClient.requestSgt(krbToken, getServerPrincipal(), cCacheFile.getPath());
            fail("Failure expected on an invalid audience");
        } catch (KrbException ex) { //NOPMD
            // expected
        }

        cCacheFile.delete();
    }

    @org.junit.Test
    public void accessTokenInvalidSignature() throws Exception {

        KrbClient client = getKrbClient();

        // Get a TGT
        TgtTicket tgt = client.requestTgt(getClientPrincipal(), getClientPassword());
        assertNotNull(tgt);

        // Write to cache
        Credential credential = new Credential(tgt);
        CredentialCache cCache = new CredentialCache();
        cCache.addCredential(credential);
        cCache.setPrimaryPrincipal(tgt.getClientPrincipal());

        File cCacheFile = File.createTempFile("krb5_" + getClientPrincipal(), "cc");
        cCache.store(cCacheFile);

        KrbTokenClient tokenClient = new KrbTokenClient(client);

        tokenClient.setKdcHost(client.getSetting().getKdcHost());
        tokenClient.setKdcTcpPort(client.getSetting().getKdcTcpPort());

        tokenClient.setKdcRealm(client.getSetting().getKdcRealm());
        tokenClient.init();

        // Create a JWT token with an invalid audience
        AuthToken authToken = issueToken(getClientPrincipal());
        authToken.isAcToken(true);
        authToken.isIdToken(false);
        authToken.setAudiences(Collections.singletonList(getServerPrincipal()));
        KrbToken krbToken = new KrbToken(authToken, TokenFormat.JWT);

        KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        krbToken.setTokenValue(signToken(authToken, keyPair.getPrivate()));

        // Now get a SGT using the JWT
        try {
            tokenClient.requestSgt(krbToken, getServerPrincipal(), cCacheFile.getPath());
            fail("Failure expected on an invalid signature");
        } catch (KrbException ex) { //NOPMD
            // expected
        }

        cCacheFile.delete();
    }

    @org.junit.Test
    public void accessTokenUnknownIssuer() throws Exception {

        KrbClient client = getKrbClient();

        // Get a TGT
        TgtTicket tgt = client.requestTgt(getClientPrincipal(), getClientPassword());
        assertNotNull(tgt);

        // Write to cache
        Credential credential = new Credential(tgt);
        CredentialCache cCache = new CredentialCache();
        cCache.addCredential(credential);
        cCache.setPrimaryPrincipal(tgt.getClientPrincipal());

        File cCacheFile = File.createTempFile("krb5_" + getClientPrincipal(), "cc");
        cCache.store(cCacheFile);

        KrbTokenClient tokenClient = new KrbTokenClient(client);

        tokenClient.setKdcHost(client.getSetting().getKdcHost());
        tokenClient.setKdcTcpPort(client.getSetting().getKdcTcpPort());

        tokenClient.setKdcRealm(client.getSetting().getKdcRealm());
        tokenClient.init();

        // Create a JWT token with an invalid audience
        AuthToken authToken = issueToken(getClientPrincipal());
        authToken.isAcToken(true);
        authToken.isIdToken(false);
        authToken.setAudiences(Collections.singletonList(getServerPrincipal()));
        authToken.setIssuer("unknown-issuer");
        KrbToken krbToken = new KrbToken(authToken, TokenFormat.JWT);

        InputStream is = Files.newInputStream(getSignKeyFile().toPath());
        PrivateKey signKey = PrivateKeyReader.loadPrivateKey(is);
        krbToken.setTokenValue(signToken(authToken, signKey));

        // Now get a SGT using the JWT
        try {
            tokenClient.requestSgt(krbToken, getServerPrincipal(), cCacheFile.getPath());
            fail("Failure expected on an unknown issuer");
        } catch (KrbException ex) { //NOPMD
            // expected
        }

        cCacheFile.delete();
    }

    // Use the TGT here instead of an armor cache
    @org.junit.Test
    public void accessTokenUsingTicket() throws Exception {

        KrbClient client = getKrbClient();

        // Get a TGT
        TgtTicket tgt = client.requestTgt(getClientPrincipal(), getClientPassword());
        assertNotNull(tgt);

        KrbTokenClient tokenClient = new KrbTokenClient(client);

        tokenClient.setKdcHost(client.getSetting().getKdcHost());
        tokenClient.setKdcTcpPort(client.getSetting().getKdcTcpPort());

        tokenClient.setKdcRealm(client.getSetting().getKdcRealm());
        tokenClient.init();

        // Create a JWT token
        AuthToken authToken = issueToken(getClientPrincipal());
        authToken.isAcToken(true);
        authToken.isIdToken(false);
        authToken.setAudiences(Collections.singletonList(getServerPrincipal()));
        KrbToken krbToken = new KrbToken(authToken, TokenFormat.JWT);

        InputStream is = Files.newInputStream(getSignKeyFile().toPath());
        PrivateKey signKey = PrivateKeyReader.loadPrivateKey(is);
        krbToken.setTokenValue(signToken(authToken, signKey));

        // Now get a SGT using the JWT
        SgtTicket tkt = tokenClient.requestSgt(krbToken, getServerPrincipal(), tgt);
        assertTrue(tkt != null);

        // Decrypt the ticket
        Ticket ticket = tkt.getTicket();
        EncryptionKey key = EncryptionHandler.string2Key(getServerPrincipal(), getServerPassword(),
                                                         ticket.getEncryptedEncPart().getEType());

        EncTicketPart encPart =
            EncryptionUtil.unseal(ticket.getEncryptedEncPart(),
                                  key, KeyUsage.KDC_REP_TICKET, EncTicketPart.class);

        // Examine the authorization data
        AuthorizationData authzData = encPart.getAuthorizationData();
        assertEquals(1, authzData.getElements().size());
        AuthorizationDataEntry dataEntry = authzData.getElements().iterator().next();
        AdToken token = dataEntry.getAuthzDataAs(AdToken.class);
        KrbToken decodedKrbToken = token.getToken();
        assertEquals(getClientPrincipal(), decodedKrbToken.getSubject());
        assertEquals(getServerPrincipal(), decodedKrbToken.getAudiences().get(0));
    }

    @org.junit.Test
    public void identityToken() throws Exception {

        KrbClient client = getKrbClient();

        // Get a TGT
        TgtTicket tgt = client.requestTgt(getClientPrincipal(), getClientPassword());
        assertNotNull(tgt);

        // Write to cache
        Credential credential = new Credential(tgt);
        CredentialCache cCache = new CredentialCache();
        cCache.addCredential(credential);
        cCache.setPrimaryPrincipal(tgt.getClientPrincipal());

        File cCacheFile = File.createTempFile("krb5_" + getClientPrincipal(), "cc");
        cCache.store(cCacheFile);

        KrbTokenClient tokenClient = new KrbTokenClient(client);

        tokenClient.setKdcHost(client.getSetting().getKdcHost());
        tokenClient.setKdcTcpPort(client.getSetting().getKdcTcpPort());

        tokenClient.setKdcRealm(client.getSetting().getKdcRealm());
        tokenClient.init();

        // Create a JWT token
        AuthToken authToken = issueToken(getClientPrincipal());
        KrbToken krbToken = new KrbToken(authToken, TokenFormat.JWT);

        InputStream is = Files.newInputStream(getSignKeyFile().toPath());
        PrivateKey signKey = PrivateKeyReader.loadPrivateKey(is);
        krbToken.setTokenValue(signToken(authToken, signKey));

        // Now get a TGT using the JWT token
        tgt = tokenClient.requestTgt(krbToken, cCacheFile.getPath());

        // Now get a SGT using the TGT
        SgtTicket tkt = tokenClient.requestSgt(tgt, getServerPrincipal());
        assertTrue(tkt != null);

        // Decrypt the ticket
        Ticket ticket = tkt.getTicket();
        EncryptionKey key = EncryptionHandler.string2Key(getServerPrincipal(), getServerPassword(),
                                                         ticket.getEncryptedEncPart().getEType());

        EncTicketPart encPart =
            EncryptionUtil.unseal(ticket.getEncryptedEncPart(),
                                  key, KeyUsage.KDC_REP_TICKET, EncTicketPart.class);

        // Check the authorization data is not present
        AuthorizationData authzData = encPart.getAuthorizationData();
        assertNull(authzData);

        cCacheFile.delete();
    }

    @org.junit.Test
    public void identityTokenInvalidAudience() throws Exception {

        KrbClient client = getKrbClient();

        // Get a TGT
        TgtTicket tgt = client.requestTgt(getClientPrincipal(), getClientPassword());
        assertNotNull(tgt);

        // Write to cache
        Credential credential = new Credential(tgt);
        CredentialCache cCache = new CredentialCache();
        cCache.addCredential(credential);
        cCache.setPrimaryPrincipal(tgt.getClientPrincipal());

        File cCacheFile = File.createTempFile("krb5_" + getClientPrincipal(), "cc");
        cCache.store(cCacheFile);

        KrbTokenClient tokenClient = new KrbTokenClient(client);

        tokenClient.setKdcHost(client.getSetting().getKdcHost());
        tokenClient.setKdcTcpPort(client.getSetting().getKdcTcpPort());

        tokenClient.setKdcRealm(client.getSetting().getKdcRealm());
        tokenClient.init();

        // Create a JWT token
        AuthToken authToken = issueToken(getClientPrincipal());
        authToken.setAudiences(Collections.singletonList(authToken.getAudiences().get(0) + "_"));
        KrbToken krbToken = new KrbToken(authToken, TokenFormat.JWT);

        InputStream is = Files.newInputStream(getSignKeyFile().toPath());
        PrivateKey signKey = PrivateKeyReader.loadPrivateKey(is);
        krbToken.setTokenValue(signToken(authToken, signKey));

        // Now get a TGT using the JWT token
        try {
            tokenClient.requestTgt(krbToken, cCacheFile.getPath());
            fail("Failure expected on an invalid audience");
        } catch (KrbException ex) { //NOPMD
            // expected
        }

        cCacheFile.delete();
    }

    @org.junit.Test
    public void identityTokenInvalidSignature() throws Exception {

        KrbClient client = getKrbClient();

        // Get a TGT
        TgtTicket tgt = client.requestTgt(getClientPrincipal(), getClientPassword());
        assertNotNull(tgt);

        // Write to cache
        Credential credential = new Credential(tgt);
        CredentialCache cCache = new CredentialCache();
        cCache.addCredential(credential);
        cCache.setPrimaryPrincipal(tgt.getClientPrincipal());

        File cCacheFile = File.createTempFile("krb5_" + getClientPrincipal(), "cc");
        cCache.store(cCacheFile);

        KrbTokenClient tokenClient = new KrbTokenClient(client);

        tokenClient.setKdcHost(client.getSetting().getKdcHost());
        tokenClient.setKdcTcpPort(client.getSetting().getKdcTcpPort());

        tokenClient.setKdcRealm(client.getSetting().getKdcRealm());
        tokenClient.init();

        // Create a JWT token
        AuthToken authToken = issueToken(getClientPrincipal());
        authToken.setAudiences(Collections.singletonList(authToken.getAudiences().get(0) + "_"));
        KrbToken krbToken = new KrbToken(authToken, TokenFormat.JWT);

        KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        krbToken.setTokenValue(signToken(authToken, keyPair.getPrivate()));

        // Now get a TGT using the JWT token
        try {
            tokenClient.requestTgt(krbToken, cCacheFile.getPath());
            fail("Failure expected on an invalid signature");
        } catch (KrbException ex) { //NOPMD
            // expected
        }

        cCacheFile.delete();
    }

    @org.junit.Test
    public void identityTokenUnknownIssuer() throws Exception {

        KrbClient client = getKrbClient();

        // Get a TGT
        TgtTicket tgt = client.requestTgt(getClientPrincipal(), getClientPassword());
        assertNotNull(tgt);

        // Write to cache
        Credential credential = new Credential(tgt);
        CredentialCache cCache = new CredentialCache();
        cCache.addCredential(credential);
        cCache.setPrimaryPrincipal(tgt.getClientPrincipal());

        File cCacheFile = File.createTempFile("krb5_" + getClientPrincipal(), "cc");
        cCache.store(cCacheFile);

        KrbTokenClient tokenClient = new KrbTokenClient(client);

        tokenClient.setKdcHost(client.getSetting().getKdcHost());
        tokenClient.setKdcTcpPort(client.getSetting().getKdcTcpPort());

        tokenClient.setKdcRealm(client.getSetting().getKdcRealm());
        tokenClient.init();

        // Create a JWT token
        AuthToken authToken = issueToken(getClientPrincipal());
        authToken.setIssuer("unknown-issuer");
        KrbToken krbToken = new KrbToken(authToken, TokenFormat.JWT);

        InputStream is = Files.newInputStream(getSignKeyFile().toPath());
        PrivateKey signKey = PrivateKeyReader.loadPrivateKey(is);
        krbToken.setTokenValue(signToken(authToken, signKey));

        // Now get a TGT using the JWT token
        try {
            tokenClient.requestTgt(krbToken, cCacheFile.getPath());
            fail("Failure expected on an unknown issuer");
        } catch (KrbException ex) { //NOPMD
            // expected
        }

        cCacheFile.delete();
    }

    private byte[] signToken(AuthToken authToken, PrivateKey signKey) throws Exception {
        TokenEncoder tokenEncoder = KrbRuntime.getTokenProvider().createTokenEncoder();
        assertTrue(tokenEncoder instanceof JwtTokenEncoder);

        ((JwtTokenEncoder) tokenEncoder).setSignKey((RSAPrivateKey) signKey);
        return tokenEncoder.encodeAsBytes(authToken);
    }
}
