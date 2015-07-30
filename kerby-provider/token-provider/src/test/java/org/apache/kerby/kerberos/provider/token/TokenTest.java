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
package org.apache.kerby.kerberos.provider.token;

import org.apache.kerby.kerberos.kerb.KrbRuntime;
import org.apache.kerby.kerberos.kerb.provider.TokenDecoder;
import org.apache.kerby.kerberos.kerb.provider.TokenEncoder;
import org.apache.kerby.kerberos.kerb.spec.base.AuthToken;
import org.assertj.core.api.Assertions;
import org.junit.Before;
import org.junit.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

public class TokenTest {

    static {
        KrbRuntime.setTokenProvider(new JwtTokenProvider());
    }

    static final String SUBJECT = "test-sub";
    static final String AUDIENCE = "krbtgt@EXAMPLE.COM";
    static final String ISSUER = "oauth2.com";
    static final String GROUP = "sales-group";
    static final String ROLE = "ADMIN";

    private AuthToken authToken;
    private List<String> auds = new ArrayList<String>();

    @Before
    public void setUp() {
        authToken = KrbRuntime.getTokenProvider().createTokenFactory().createToken();

        authToken.setIssuer(ISSUER);
        authToken.setSubject(SUBJECT);

        authToken.addAttribute("group", GROUP);
        authToken.addAttribute("role", ROLE);

        auds.add(AUDIENCE);
        authToken.setAudiences(auds);

        // Set expiration in 60 minutes
        final Date now =  new Date(new Date().getTime() / 1000 * 1000);
        Date exp = new Date(now.getTime() + 1000 * 60 * 60);
        authToken.setExpirationTime(exp);

        Date nbf = now;
        authToken.setNotBeforeTime(nbf);

        Date iat = now;
        authToken.setIssueTime(iat);
    }

    @Test
    public void testToken() throws Exception {
        TokenEncoder tokenEncoder = KrbRuntime.getTokenProvider().createTokenEncoder();
        String tokenStr = tokenEncoder.encodeAsString(authToken);
        Assertions.assertThat(tokenStr).isNotNull();

        TokenDecoder tokenDecoder = KrbRuntime.getTokenProvider().createTokenDecoder();

        setAudience((JwtTokenDecoder) tokenDecoder, auds);

        AuthToken token2 = tokenDecoder.decodeFromString(tokenStr);
        Assertions.assertThat(token2.getSubject()).isEqualTo(SUBJECT);
        Assertions.assertThat(token2.getIssuer()).isEqualTo(ISSUER);
    }

    @Test
    public void testDecodeFromBytes() throws Exception {
        TokenEncoder tokenEncoder = KrbRuntime.getTokenProvider().createTokenEncoder();
        byte[] tokenStr = tokenEncoder.encodeAsBytes(authToken);
        Assertions.assertThat(tokenStr).isNotNull();

        TokenDecoder tokenDecoder = KrbRuntime.getTokenProvider().createTokenDecoder();

        setAudience((JwtTokenDecoder) tokenDecoder, auds);

        AuthToken token2 = tokenDecoder.decodeFromBytes(tokenStr);
        Assertions.assertThat(token2.getSubject()).isEqualTo(SUBJECT);
        Assertions.assertThat(token2.getIssuer()).isEqualTo(ISSUER);
    }

    @Test
    public void testTokenWithEncryptedJWT() throws Exception {
        TokenEncoder tokenEncoder = KrbRuntime.getTokenProvider().createTokenEncoder();
        TokenDecoder tokenDecoder = KrbRuntime.getTokenProvider().createTokenDecoder();

        setEncryptKey((JwtTokenEncoder) tokenEncoder, (JwtTokenDecoder) tokenDecoder);
        setAudience((JwtTokenDecoder) tokenDecoder, auds);

        String tokenStr = tokenEncoder.encodeAsString(authToken);
        Assertions.assertThat(tokenStr).isNotNull();

        AuthToken token2 = tokenDecoder.decodeFromString(tokenStr);
        Assertions.assertThat(token2.getSubject()).isEqualTo(SUBJECT);
        Assertions.assertThat(token2.getIssuer()).isEqualTo(ISSUER);
    }

    @Test
    public void testTokenWithSignedJWT() throws Exception {
        TokenEncoder tokenEncoder = KrbRuntime.getTokenProvider().createTokenEncoder();
        TokenDecoder tokenDecoder = KrbRuntime.getTokenProvider().createTokenDecoder();

        setSignKey((JwtTokenEncoder) tokenEncoder, (JwtTokenDecoder) tokenDecoder);
        setAudience((JwtTokenDecoder) tokenDecoder, auds);

        String tokenStr = tokenEncoder.encodeAsString(authToken);
        Assertions.assertThat(tokenStr).isNotNull();

        AuthToken token2 = tokenDecoder.decodeFromString(tokenStr);
        Assertions.assertThat(token2.getSubject()).isEqualTo(SUBJECT);
        Assertions.assertThat(token2.getIssuer()).isEqualTo(ISSUER);
    }

    @Test
    public void testTokenWithSingedAndEncryptedJWT() throws Exception {
        TokenEncoder tokenEncoder = KrbRuntime.getTokenProvider().createTokenEncoder();
        TokenDecoder tokenDecoder = KrbRuntime.getTokenProvider().createTokenDecoder();

        setSignKey((JwtTokenEncoder) tokenEncoder, (JwtTokenDecoder) tokenDecoder);
        setEncryptKey((JwtTokenEncoder) tokenEncoder, (JwtTokenDecoder) tokenDecoder);
        setAudience((JwtTokenDecoder) tokenDecoder, auds);

        String tokenStr = tokenEncoder.encodeAsString(authToken);
        Assertions.assertThat(tokenStr).isNotNull();

        AuthToken token2 = tokenDecoder.decodeFromString(tokenStr);
        Assertions.assertThat(token2.getSubject()).isEqualTo(SUBJECT);
        Assertions.assertThat(token2.getIssuer()).isEqualTo(ISSUER);
    }

    @Test
    public void testInvalidAudienceJWT() throws Exception {
        List<String> audiences = new ArrayList<String>();
        audiences.add("invalid@EXAMPLE.COM");

        TokenEncoder tokenEncoder = KrbRuntime.getTokenProvider().createTokenEncoder();
        TokenDecoder tokenDecoder = KrbRuntime.getTokenProvider().createTokenDecoder();

        setSignKey((JwtTokenEncoder) tokenEncoder, (JwtTokenDecoder) tokenDecoder);
        setEncryptKey((JwtTokenEncoder) tokenEncoder, (JwtTokenDecoder) tokenDecoder);
        setAudience((JwtTokenDecoder) tokenDecoder, audiences);

        String tokenStr = tokenEncoder.encodeAsString(authToken);
        Assertions.assertThat(tokenStr).isNotNull();

        AuthToken token2 = tokenDecoder.decodeFromString(tokenStr);
        Assertions.assertThat(token2).isNull();
    }

    @Test
    public void testExpiredJWT() throws Exception {
        authToken.setExpirationTime(new Date(new Date().getTime() - 100));

        TokenEncoder tokenEncoder = KrbRuntime.getTokenProvider().createTokenEncoder();
        TokenDecoder tokenDecoder = KrbRuntime.getTokenProvider().createTokenDecoder();

        setSignKey((JwtTokenEncoder) tokenEncoder, (JwtTokenDecoder) tokenDecoder);
        setEncryptKey((JwtTokenEncoder) tokenEncoder, (JwtTokenDecoder) tokenDecoder);
        setAudience((JwtTokenDecoder) tokenDecoder, auds);

        String tokenStr = tokenEncoder.encodeAsString(authToken);
        Assertions.assertThat(tokenStr).isNotNull();

        AuthToken token2 = tokenDecoder.decodeFromString(tokenStr);
        Assertions.assertThat(token2).isNull();
    }

    private void setEncryptKey(JwtTokenEncoder encoder, JwtTokenDecoder decoder) {
        KeyPair encryptionKeyPair = getKeyPair();
        encoder.setEncryptionKey((RSAPublicKey) encryptionKeyPair.getPublic());
        decoder.setDecryptionKey((RSAPrivateKey) encryptionKeyPair.getPrivate());
    }

    private KeyPair getKeyPair() {
        KeyPairGenerator kpg = null;
        try {
            kpg = KeyPairGenerator.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return kpg.generateKeyPair();
    }

    private void setSignKey(JwtTokenEncoder encoder, JwtTokenDecoder decoder) {
        KeyPair signKeyPair = getKeyPair();
        encoder.setSignKey((RSAPrivateKey) signKeyPair.getPrivate());
        decoder.setVerifyKey((RSAPublicKey) signKeyPair.getPublic());
    }

    private void setAudience(JwtTokenDecoder decoder, List<String> auds) {
        decoder.setAudiences(auds);
    }
}