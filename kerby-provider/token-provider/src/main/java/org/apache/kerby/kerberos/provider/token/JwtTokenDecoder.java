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

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import org.apache.kerby.kerberos.kerb.provider.TokenDecoder;
import org.apache.kerby.kerberos.kerb.spec.base.AuthToken;

import java.io.IOException;
import java.nio.charset.Charset;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.Date;
import java.util.List;

/**
 * JWT token decoder, implemented using Nimbus JWT library.
 */
public class JwtTokenDecoder implements TokenDecoder {
    private RSAPrivateKey decryptionKey;
    private RSAPublicKey verifyKey;
    private List<String> audiences = null;

    /**
     * {@inheritDoc}
     */
    @Override
    public AuthToken decodeFromBytes(byte[] content) throws IOException {
        String tokenStr = new String(content, Charset.forName("UTF-8"));

        return decodeFromString(tokenStr);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public AuthToken decodeFromString(String content) throws IOException {
       JWT jwt = null;
        try {
            jwt = JWTParser.parse(content);
        } catch (ParseException e) {
            // Invalid JWT encoding
            throw new IOException("Failed to parse JWT token string", e);
        }

        // Check the JWT type
        if (jwt instanceof PlainJWT) {
            PlainJWT plainObject = (PlainJWT) jwt;
            try {

                if (verifyToken(jwt)) {
                    return new JwtAuthToken(plainObject.getJWTClaimsSet());
                } else {
                    return null;
                }
            } catch (ParseException e) {
                throw new IOException("Failed to get JWT claims set", e);
            }
        } else if (jwt instanceof EncryptedJWT) {
            EncryptedJWT encryptedJWT = (EncryptedJWT) jwt;
            decryptEncryptedJWT(encryptedJWT);
            SignedJWT signedJWT = encryptedJWT.getPayload().toSignedJWT();
            if (signedJWT != null) {
                boolean success = verifySignedJWT(signedJWT) && verifyToken(signedJWT);
                if (success) {
                    try {
                        return new JwtAuthToken(signedJWT.getJWTClaimsSet());
                    } catch (ParseException e) {
                        throw new IOException("Failed to get JWT claims set", e);
                    }
                } else {
                    return null;
                }
            } else {
                try {
                    if (verifyToken(encryptedJWT)) {
                        return new JwtAuthToken(encryptedJWT.getJWTClaimsSet());
                    } else {
                        return null;
                    }
                } catch (ParseException e) {
                    throw new IOException("Failed to get JWT claims set", e);
                }
            }
        } else if (jwt instanceof SignedJWT) {
            SignedJWT signedJWT = (SignedJWT) jwt;
            boolean success = verifySignedJWT(signedJWT) && verifyToken(signedJWT);
            if (success) {
                try {
                    return new JwtAuthToken(signedJWT.getJWTClaimsSet());
                } catch (ParseException e) {
                    throw new IOException("Failed to get JWT claims set", e);
                }
            } else {
                return null;
            }
        } else {
            throw new IOException("Unexpected JWT type: " + jwt);
        }
    }

    /**
     * Decrypt the Encrypted JWT
     *
     * @throws java.io.IOException e
     * @param encryptedJWT an encrypted JWT
     */
    public void decryptEncryptedJWT(EncryptedJWT encryptedJWT) throws IOException {
        RSADecrypter decrypter = new RSADecrypter(decryptionKey);
        try {
            encryptedJWT.decrypt(decrypter);
        } catch (JOSEException e) {
            throw new IOException("Failed to decrypt the encrypted JWT", e);
        }
    }

    /**
     * Set the decryption key
     *
     * @param key a private key
     */
    public void setDecryptionKey(RSAPrivateKey key) {
        decryptionKey = key;
    }

    /**
     * verify the Signed JWT
     *
     * @throws java.io.IOException e
     * @param signedJWT a signed JWT
     * @return whether verify success
     */
    public boolean verifySignedJWT(SignedJWT signedJWT) throws IOException {
        JWSVerifier verifier = new RSASSAVerifier(verifyKey);
        try {
            return signedJWT.verify(verifier);
        } catch (JOSEException e) {
            throw new IOException("Failed to verify the signed JWT", e);
        }
    }

    /**
     * set the verify key
     *
     * @param key a public key
     */
    public void setVerifyKey(RSAPublicKey key) {
        verifyKey = key;
    }

    /**
     * set the token audiences
     *
     * @param auds the list of token audiences
     */
    public void setAudiences(List<String> auds) {
        audiences = auds;
    }

    private boolean verifyToken(JWT jwtToken) throws IOException {
        boolean audValid = verifyAudiences(jwtToken);
        boolean expValid = verifyExpiration(jwtToken);
        return  audValid && expValid;
    }

    private boolean verifyAudiences(JWT jwtToken) throws IOException {
        boolean valid = false;
        try {
            List<String> tokenAudiences = jwtToken.getJWTClaimsSet().getAudience();
            if (audiences == null) {
                valid = true;
            } else {
                for (String audience : tokenAudiences) {
                    if (audiences.contains(audience)) {
                        valid = true;
                        break;
                    }
                }
            }
        } catch (ParseException e) {
            throw new IOException("Failed to get JWT claims set", e);
        }
        return valid;
    }

    private boolean verifyExpiration(JWT jwtToken) throws IOException {
        boolean valid = false;
        try {
            Date expire = jwtToken.getJWTClaimsSet().getExpirationTime();
            if (expire != null && new Date().before(expire)) {
                valid = true;
            }
        } catch (ParseException e) {
            throw new IOException("Failed to get JWT claims set", e);
        }
        return valid;
    }
}
