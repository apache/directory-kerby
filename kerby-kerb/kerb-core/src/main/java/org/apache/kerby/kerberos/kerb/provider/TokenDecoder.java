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
package org.apache.kerby.kerberos.kerb.provider;

import org.apache.kerby.kerberos.kerb.type.base.AuthToken;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * An AuthToken decoder.
 */
public interface TokenDecoder {

    /**
     * Decode a token from a bytes array.
     * @param content The content
     * @return token
     * @throws IOException e
     */
    AuthToken decodeFromBytes(byte[] content) throws IOException;

    /**
     * Decode a token from a string.
     * @param content The content
     * @return token
     * @throws IOException e
     */
    AuthToken decodeFromString(String content) throws IOException;

    /**
     * set the verify key
     *
     * @param key a public key
     */
    void setVerifyKey(PublicKey key);

    /**
     * set the verify key
     *
     * @param key a byte[] key
     */
    void setVerifyKey(byte[] key);

    /**
     * Set the decryption key
     *
     * @param key a private key
     */
    void setDecryptionKey(PrivateKey key);

    /**
     * Set the decryption key
     *
     * @param key a secret key
     */
    void setDecryptionKey(byte[] key);

    /**
     * The token signed or not
     *
     * @return signed or not signed
     */
    boolean isSigned();
}
