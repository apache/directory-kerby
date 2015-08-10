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
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.SignedJWT;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.provider.TokenEncoder;
import org.apache.kerby.kerberos.kerb.spec.base.AuthToken;

import java.nio.charset.Charset;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;

/**
 * JWT token encoder, implemented using Nimbus JWT library.
 */
public class JwtTokenEncoder implements TokenEncoder {
    private static JWEAlgorithm jweAlgorithm = JWEAlgorithm.RSA_OAEP;
    private static EncryptionMethod encryptionMethod = EncryptionMethod.A128GCM;
    private static JWSAlgorithm jwsAlgorithm = JWSAlgorithm.RS256;
    private RSAPublicKey encryptionKey;
    private RSAPrivateKey signKey;

    /**
     * {@inheritDoc}
     */
    @Override
    public byte[] encodeAsBytes(AuthToken token) throws KrbException {
        String tokenStr = encodeAsString(token);
        return tokenStr.getBytes(Charset.forName("UTF-8"));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String encodeAsString(AuthToken token) throws KrbException {
        if (!(token instanceof JwtAuthToken)) {
            throw new KrbException("Unexpected AuthToken, not JwtAuthToken");
        }

        JwtAuthToken jwtAuthToken = (JwtAuthToken) token;
        JWT jwt = jwtAuthToken.getJwt();

        String tokenStr = null;
        if (signKey != null) {
            // Create signer with the private key
            JWSSigner signer = new RSASSASigner(signKey);
            SignedJWT signedJWT = null;
            try {
                signedJWT = new SignedJWT(new JWSHeader(jwsAlgorithm), jwt.getJWTClaimsSet());
            } catch (ParseException e) {
                throw new KrbException("Failed to get JWT claims set", e);
            }
            try {
                signedJWT.sign(signer);
            } catch (JOSEException e) {
                throw new KrbException("Failed to sign the Signed JWT", e);
            }
            // Encrypt
            if (encryptionKey != null) {
                // Create JWE object with signedJWT as payload
                JWEObject jweObject = new JWEObject(
                        new JWEHeader.Builder(jweAlgorithm, encryptionMethod).contentType("JWT").build(),
                        new Payload(signedJWT));
                try {
                    jweObject.encrypt(new RSAEncrypter(encryptionKey));
                } catch (JOSEException e) {
                    throw new KrbException("Failed to encrypt the JWE object", e);
                }
                tokenStr = jweObject.serialize();
            } else {
                tokenStr = signedJWT.serialize();
            }
        } else if (encryptionKey != null) {
            JWEHeader header = new JWEHeader(jweAlgorithm, encryptionMethod);
            EncryptedJWT encryptedJWT = null;
            try {
                encryptedJWT = new EncryptedJWT(header, jwt.getJWTClaimsSet());
            } catch (ParseException e) {
                throw new KrbException("Failed to get JWT claims set", e);
            }
            try {
                encryptedJWT.encrypt(new RSAEncrypter(encryptionKey));
            } catch (JOSEException e) {
                throw new KrbException("Failed to encrypt the encrypted JWT", e);
            }
            tokenStr = encryptedJWT.serialize();

        } else {
            tokenStr = jwt.serialize();
        }
        return tokenStr;
    }

    /**
     * set the encryption key
     *
     * @param key a public key
     */
    public void setEncryptionKey(RSAPublicKey key) {
        encryptionKey = key;
    }

    /**
     * set the sign key
     *
     * @param key a private key
     */
    public void setSignKey(RSAPrivateKey key) {
        signKey = key;
    }
}
