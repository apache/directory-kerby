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

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWSAlgorithm;
import org.apache.kerby.kerberos.kerb.KrbRuntime;
import org.apache.kerby.kerberos.kerb.provider.TokenDecoder;
import org.apache.kerby.kerberos.kerb.provider.TokenEncoder;
import org.apache.kerby.kerberos.kerb.type.base.AuthToken;
import org.assertj.core.api.Assertions;
import org.junit.Before;
import org.junit.Test;

import javax.crypto.KeyGenerator;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

public class TokenTest {

    static final String SUBJECT = "test-sub";
    static final String AUDIENCE = "krbtgt@EXAMPLE.COM";
    static final String ISSUER = "oauth2.com";
    static final String GROUP = "sales-group";
    static final String ROLE = "ADMIN";

    private AuthToken authToken;
    private List<String> auds = new ArrayList<>();
    private EncryptionMethod encryptionMethod = EncryptionMethod.A128GCM;

    @Before
    public void setUp() {
        authToken = KrbRuntime.getTokenProvider("JWT").createTokenFactory().createToken();

        authToken.setIssuer(ISSUER);
        authToken.setSubject(SUBJECT);

        authToken.addAttribute("group", GROUP);
        authToken.addAttribute("role", ROLE);

        auds.add(AUDIENCE);
        authToken.setAudiences(auds);

        // Set expiration in 60 minutes
        final Date now = new Date();
        Date exp = new Date(now.getTime() + 1000 * 60 * 60);
        authToken.setExpirationTime(exp);

        Date nbf = now;
        authToken.setNotBeforeTime(nbf);

        Date iat = now;
        authToken.setIssueTime(iat);

        String jsv = System.getProperty("java.specification.version");
        if (jsv != null && Double.parseDouble(jsv) == 1.7) {
            encryptionMethod = EncryptionMethod.A128CBC_HS256;
        }

    }

    @Test
    public void testToken() throws Exception {
        TokenEncoder tokenEncoder = KrbRuntime.getTokenProvider("JWT").createTokenEncoder();
        ((JwtTokenEncoder) tokenEncoder).setEncryptionMethod(encryptionMethod);
        String tokenStr = tokenEncoder.encodeAsString(authToken);
        Assertions.assertThat(tokenStr).isNotNull();

        TokenDecoder tokenDecoder = KrbRuntime.getTokenProvider("JWT").createTokenDecoder();

        setAudience((JwtTokenDecoder) tokenDecoder, auds);

        AuthToken token2 = tokenDecoder.decodeFromString(tokenStr);
        Assertions.assertThat(token2.getSubject()).isEqualTo(SUBJECT);
        Assertions.assertThat(token2.getIssuer()).isEqualTo(ISSUER);
    }

    @Test
    public void testDecodeFromBytes() throws Exception {
        TokenEncoder tokenEncoder = KrbRuntime.getTokenProvider("JWT").createTokenEncoder();
        ((JwtTokenEncoder) tokenEncoder).setEncryptionMethod(encryptionMethod);
        byte[] tokenStr = tokenEncoder.encodeAsBytes(authToken);
        Assertions.assertThat(tokenStr).isNotNull();

        TokenDecoder tokenDecoder = KrbRuntime.getTokenProvider("JWT").createTokenDecoder();

        setAudience((JwtTokenDecoder) tokenDecoder, auds);

        AuthToken token2 = tokenDecoder.decodeFromBytes(tokenStr);
        Assertions.assertThat(token2.getSubject()).isEqualTo(SUBJECT);
        Assertions.assertThat(token2.getIssuer()).isEqualTo(ISSUER);
    }

    @Test
    public void testTokenWithEncryptedJWT() throws Exception {
        TokenEncoder tokenEncoder = KrbRuntime.getTokenProvider("JWT").createTokenEncoder();
        ((JwtTokenEncoder) tokenEncoder).setEncryptionMethod(encryptionMethod);
        TokenDecoder tokenDecoder = KrbRuntime.getTokenProvider("JWT").createTokenDecoder();

        setEncryptKey((JwtTokenEncoder) tokenEncoder, (JwtTokenDecoder) tokenDecoder);
        setAudience((JwtTokenDecoder) tokenDecoder, auds);

        String tokenStr = tokenEncoder.encodeAsString(authToken);
        Assertions.assertThat(tokenStr).isNotNull();

        AuthToken token2 = tokenDecoder.decodeFromString(tokenStr);
        Assertions.assertThat(token2.getSubject()).isEqualTo(SUBJECT);
        Assertions.assertThat(token2.getIssuer()).isEqualTo(ISSUER);
    }

    @Test
    public void testTokenWithDirectEncryptedJWT() throws Exception {
        if (EncryptionMethod.A128CBC_HS256.equals(encryptionMethod)) {
            // Only run this test with JDK8
            return;
        }
        TokenEncoder tokenEncoder = KrbRuntime.getTokenProvider("JWT").createTokenEncoder();
        TokenDecoder tokenDecoder = KrbRuntime.getTokenProvider("JWT").createTokenDecoder();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128);
        byte[] secretKey = keyGenerator.generateKey().getEncoded();

        ((JwtTokenEncoder) tokenEncoder).setEncryptionKey(secretKey);
        ((JwtTokenEncoder) tokenEncoder).setJweAlgorithm(JWEAlgorithm.DIR);
        ((JwtTokenDecoder) tokenDecoder).setDecryptionKey(secretKey);
        setAudience((JwtTokenDecoder) tokenDecoder, auds);

        String tokenStr = tokenEncoder.encodeAsString(authToken);
        Assertions.assertThat(tokenStr).isNotNull();

        AuthToken token2 = tokenDecoder.decodeFromString(tokenStr);
        Assertions.assertThat(token2.getSubject()).isEqualTo(SUBJECT);
        Assertions.assertThat(token2.getIssuer()).isEqualTo(ISSUER);

        // Now try with a different secret key
        secretKey = keyGenerator.generateKey().getEncoded();
        ((JwtTokenDecoder) tokenDecoder).setDecryptionKey(secretKey);

        try {
            tokenDecoder.decodeFromString(tokenStr);
            Assertions.fail("Failure expected on a bad secret key");
        } catch (IOException ex) {
            String expectedError = "Failed to decrypt the encrypted JWT";
            Assertions.assertThat(ex.getMessage()).contains(expectedError);
            // expected
        }
    }

    @Test
    public void testTokenWithSignedJWT() throws Exception {
        TokenEncoder tokenEncoder = KrbRuntime.getTokenProvider("JWT").createTokenEncoder();
        ((JwtTokenEncoder) tokenEncoder).setEncryptionMethod(encryptionMethod);
        TokenDecoder tokenDecoder = KrbRuntime.getTokenProvider("JWT").createTokenDecoder();

        setSignKey((JwtTokenEncoder) tokenEncoder, (JwtTokenDecoder) tokenDecoder);
        setAudience((JwtTokenDecoder) tokenDecoder, auds);

        String tokenStr = tokenEncoder.encodeAsString(authToken);
        Assertions.assertThat(tokenStr).isNotNull();

        AuthToken token2 = tokenDecoder.decodeFromString(tokenStr);
        Assertions.assertThat(token2.getSubject()).isEqualTo(SUBJECT);
        Assertions.assertThat(token2.getIssuer()).isEqualTo(ISSUER);
    }

    @Test
    public void testTokenWithHMACSignedJWT() throws Exception {
        TokenEncoder tokenEncoder = KrbRuntime.getTokenProvider("JWT").createTokenEncoder();
        ((JwtTokenEncoder) tokenEncoder).setEncryptionMethod(encryptionMethod);
        TokenDecoder tokenDecoder = KrbRuntime.getTokenProvider("JWT").createTokenDecoder();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256);
        byte[] secretKey = keyGenerator.generateKey().getEncoded();

        ((JwtTokenEncoder) tokenEncoder).setSignKey(secretKey);
        ((JwtTokenEncoder) tokenEncoder).setJwsAlgorithm(JWSAlgorithm.HS256);
        ((JwtTokenDecoder) tokenDecoder).setVerifyKey(secretKey);
        setAudience((JwtTokenDecoder) tokenDecoder, auds);

        String tokenStr = tokenEncoder.encodeAsString(authToken);
        Assertions.assertThat(tokenStr).isNotNull();

        AuthToken token2 = tokenDecoder.decodeFromString(tokenStr);
        Assertions.assertThat(token2.getSubject()).isEqualTo(SUBJECT);
        Assertions.assertThat(token2.getIssuer()).isEqualTo(ISSUER);

        // Now try with a different secret key
        secretKey = keyGenerator.generateKey().getEncoded();
        ((JwtTokenDecoder) tokenDecoder).setVerifyKey(secretKey);

       token2 = tokenDecoder.decodeFromString(tokenStr);
       Assertions.assertThat(token2).isNull();
    }

    @Test
    @org.junit.Ignore
    // TODO: building error with openjdk8: NoSuchAlgorithm EC KeyPairGenerato..
    public void testTokenWithECDSASignedJWT() throws Exception {
        TokenEncoder tokenEncoder = KrbRuntime.getTokenProvider("JWT").createTokenEncoder();
        ((JwtTokenEncoder) tokenEncoder).setEncryptionMethod(encryptionMethod);
        TokenDecoder tokenDecoder = KrbRuntime.getTokenProvider("JWT").createTokenDecoder();

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        KeyPair keyPair = kpg.generateKeyPair();

        ((JwtTokenEncoder) tokenEncoder).setSignKey(keyPair.getPrivate());
        ((JwtTokenEncoder) tokenEncoder).setJwsAlgorithm(JWSAlgorithm.ES256);
        ((JwtTokenDecoder) tokenDecoder).setVerifyKey(keyPair.getPublic());
        setAudience((JwtTokenDecoder) tokenDecoder, auds);

        String tokenStr = tokenEncoder.encodeAsString(authToken);
        Assertions.assertThat(tokenStr).isNotNull();

        AuthToken token2 = tokenDecoder.decodeFromString(tokenStr);
        Assertions.assertThat(token2.getSubject()).isEqualTo(SUBJECT);
        Assertions.assertThat(token2.getIssuer()).isEqualTo(ISSUER);
    }

    @Test
    public void testTokenWithSignedAndEncryptedJWT() throws Exception {
        TokenEncoder tokenEncoder = KrbRuntime.getTokenProvider("JWT").createTokenEncoder();
        ((JwtTokenEncoder) tokenEncoder).setEncryptionMethod(encryptionMethod);
        TokenDecoder tokenDecoder = KrbRuntime.getTokenProvider("JWT").createTokenDecoder();

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
        List<String> audiences = new ArrayList<>();
        audiences.add("invalid@EXAMPLE.COM");

        TokenEncoder tokenEncoder = KrbRuntime.getTokenProvider("JWT").createTokenEncoder();
        ((JwtTokenEncoder) tokenEncoder).setEncryptionMethod(encryptionMethod);
        TokenDecoder tokenDecoder = KrbRuntime.getTokenProvider("JWT").createTokenDecoder();

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

        TokenEncoder tokenEncoder = KrbRuntime.getTokenProvider("JWT").createTokenEncoder();
        ((JwtTokenEncoder) tokenEncoder).setEncryptionMethod(encryptionMethod);
        TokenDecoder tokenDecoder = KrbRuntime.getTokenProvider("JWT").createTokenDecoder();

        setSignKey((JwtTokenEncoder) tokenEncoder, (JwtTokenDecoder) tokenDecoder);
        setEncryptKey((JwtTokenEncoder) tokenEncoder, (JwtTokenDecoder) tokenDecoder);
        setAudience((JwtTokenDecoder) tokenDecoder, auds);

        String tokenStr = tokenEncoder.encodeAsString(authToken);
        Assertions.assertThat(tokenStr).isNotNull();

        AuthToken token2 = tokenDecoder.decodeFromString(tokenStr);
        Assertions.assertThat(token2).isNull();
    }

    @Test
    public void testNotBeforeTime() throws Exception {
        authToken.setNotBeforeTime(new Date(new Date().getTime() + 1000 * 60));

        TokenEncoder tokenEncoder = KrbRuntime.getTokenProvider("JWT").createTokenEncoder();
        ((JwtTokenEncoder) tokenEncoder).setEncryptionMethod(encryptionMethod);
        TokenDecoder tokenDecoder = KrbRuntime.getTokenProvider("JWT").createTokenDecoder();

        setSignKey((JwtTokenEncoder) tokenEncoder, (JwtTokenDecoder) tokenDecoder);
        setEncryptKey((JwtTokenEncoder) tokenEncoder, (JwtTokenDecoder) tokenDecoder);
        setAudience((JwtTokenDecoder) tokenDecoder, auds);

        String tokenStr = tokenEncoder.encodeAsString(authToken);
        Assertions.assertThat(tokenStr).isNotNull();

        AuthToken token2 = tokenDecoder.decodeFromString(tokenStr);
        Assertions.assertThat(token2).isNull();
    }

    private void setEncryptKey(JwtTokenEncoder encoder, JwtTokenDecoder decoder) throws NoSuchAlgorithmException {
        KeyPair encryptionKeyPair = getKeyPair();
        encoder.setEncryptionKey((RSAPublicKey) encryptionKeyPair.getPublic());
        decoder.setDecryptionKey((RSAPrivateKey) encryptionKeyPair.getPrivate());
    }

    private KeyPair getKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        return kpg.generateKeyPair();
    }

    private void setSignKey(JwtTokenEncoder encoder, JwtTokenDecoder decoder) throws NoSuchAlgorithmException {
        KeyPair signKeyPair = getKeyPair();
        encoder.setSignKey((RSAPrivateKey) signKeyPair.getPrivate());
        decoder.setVerifyKey((RSAPublicKey) signKeyPair.getPublic());
    }

    private void setAudience(JwtTokenDecoder decoder, List<String> auds) {
        decoder.setAudiences(auds);
    }
}
