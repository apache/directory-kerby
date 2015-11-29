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

import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.type.base.AuthToken;

import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * An AuthToken encoder.
 */
public interface TokenEncoder {

    /**
     * Encode a token resulting in a bytes array.
     * @param token The auth token
     * @return bytes array
     * @throws KrbException e
     */
    byte[] encodeAsBytes(AuthToken token) throws KrbException;

    /**
     * Encode a token resulting in a string.
     * @param token The auth token
     * @return string representation
     * @throws KrbException e
     */
    String encodeAsString(AuthToken token) throws KrbException;

    /**
     * set the encryption key
     *
     * @param key a public key
     */
    void setEncryptionKey(PublicKey key);

    /**
     * set the encryption key
     *
     * @param key a secret key
     */
    void setEncryptionKey(byte[] key);

    /**
     * set the sign key
     *
     * @param key a private key
     */
    void setSignKey(PrivateKey key);

    /**
     * set the sign key
     *
     * @param key a secret key
     */
    void setSignKey(byte[] key);

}
