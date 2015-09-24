/*
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
package org.apache.kerby.kerberos.kerb.client.preauth.pkinit;


import junit.framework.TestCase;

import java.security.SecureRandom;
import java.util.Arrays;


/**
 * Tests the Diffie-Hellman key agreement protocol between a client and server.
 * <p/>
 * Generating a Secret Key Using the Diffie-Hellman Key Agreement Algorithm
 * <p/>
 * Two parties use a key agreement protocol to generate identical secret keys for
 * encryption without ever having to transmit the secret key. The protocol works
 * by both parties agreeing on a set of values (a prime, a base, and a private
 * value) which are used to generate a key pair.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 * @version $Rev$, $Date$
 */
public class DhKeyAgreementTest extends TestCase {
    private static SecureRandom secureRandom = new SecureRandom();


    /**
     * Tests Diffie-Hellman using Oakley 1024-bit Modular Exponential (MODP)
     * well-known group 2 [RFC2412].
     *
     * @throws Exception
     */
    public void testPreGeneratedDhParams() throws Exception {
        DhClient client = new DhClient();
        DhServer server = new DhServer();

        byte[] clientPubKeyEnc = client.init(DhGroup.MODP_GROUP2);
        byte[] serverPubKeyEnc = server.initAndDoPhase(clientPubKeyEnc);

        server.generateKey(null, null);

        client.doPhase(serverPubKeyEnc);

        client.generateKey(null, null);

        byte[] clearText = "This is just an example".getBytes();

        byte[] cipherText = server.encryptAes(clearText);
        byte[] recovered = client.decryptAes(cipherText);

        assertTrue(Arrays.equals(clearText, recovered));
    }


    /**
     * Tests Diffie-Hellman using Oakley 1024-bit Modular Exponential (MODP)
     * well-known group 2 [RFC2412], including the optional DH nonce.
     * <p/>
     * "This nonce string MUST be as long as the longest key length of the symmetric
     * key types that the client supports.  This nonce MUST be chosen randomly."
     *
     * @throws Exception
     */
    public void testPreGeneratedDhParamsWithNonce() throws Exception {
        byte[] clientDhNonce = new byte[16];
        secureRandom.nextBytes(clientDhNonce);

        byte[] serverDhNonce = new byte[16];
        secureRandom.nextBytes(serverDhNonce);

        DhClient client = new DhClient();
        DhServer server = new DhServer();

        byte[] clientPubKeyEnc = client.init(DhGroup.MODP_GROUP2);
        byte[] serverPubKeyEnc = server.initAndDoPhase(clientPubKeyEnc);

        server.generateKey(clientDhNonce, serverDhNonce);

        client.doPhase(serverPubKeyEnc);

        client.generateKey(clientDhNonce, serverDhNonce);

        byte[] clearText = "This is just an example".getBytes();

        byte[] cipherText = server.encryptAes(clearText);
        byte[] recovered = client.decryptAes(cipherText);

        assertTrue(Arrays.equals(clearText, recovered));
    }
}
