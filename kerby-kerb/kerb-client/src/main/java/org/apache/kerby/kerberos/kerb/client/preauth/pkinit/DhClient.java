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


import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.X509EncodedKeySpec;


/**
 * The client-side of Diffie-Hellman key agreement for Kerberos PKINIT.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 * @version $Rev$, $Date$
 */
class DhClient {
    private static AlgorithmParameterSpec aesIv = new IvParameterSpec(new byte[16]);

    private KeyAgreement clientKeyAgree;
    private SecretKey clientAesKey;


    DHPublicKey init(DHParameterSpec dhParamSpec) throws Exception {
        // The client creates its own DH key pair, using the DH parameters from above.
        KeyPairGenerator clientKpairGen = KeyPairGenerator.getInstance("DH");
        clientKpairGen.initialize(dhParamSpec);
        KeyPair clientKpair = clientKpairGen.generateKeyPair();

        // The client creates and initializes its DH KeyAgreement object.
        clientKeyAgree = KeyAgreement.getInstance("DH");
        clientKeyAgree.init(clientKpair.getPrivate());

        // The client encodes its public key, and sends it over to the server.
//        return clientKpair.getPublic().getEncoded();
        return (DHPublicKey) clientKpair.getPublic();
    }


    void doPhase(byte[] serverPubKeyEnc) throws Exception {
        /*
         * The client uses the server's public key for the first (and only) phase
         * of its version of the DH protocol.  Before it can do so, it has to
         * instantiate a DH public key from the server's encoded key material.
         */
        KeyFactory clientKeyFac = KeyFactory.getInstance("DH");
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(serverPubKeyEnc);
        PublicKey serverPubKey = clientKeyFac.generatePublic(x509KeySpec);

        clientKeyAgree.doPhase(serverPubKey, true);
    }


    byte[] generateKey(byte[] clientDhNonce, byte[] serverDhNonce) {
        // ZZ length will be same as public key.
        byte[] dhSharedSecret = clientKeyAgree.generateSecret();
        byte[] x = dhSharedSecret;

        if (clientDhNonce != null && clientDhNonce.length > 0
                && serverDhNonce != null && serverDhNonce.length > 0) {
            x = concatenateBytes(dhSharedSecret, clientDhNonce);
            x = concatenateBytes(x, serverDhNonce);
        }

        byte[] secret = OctetString2Key.kTruncate(dhSharedSecret.length, x);
        clientAesKey = new SecretKeySpec(secret, 0, 16, "AES");

        return clientAesKey.getEncoded();
    }


    /**
     * Decrypt using AES in CTS mode.
     *
     * @param cipherText
     * @return
     * @throws Exception
     */
    byte[] decryptAes(byte[] cipherText) throws Exception {
        // Use the secret key to encrypt/decrypt data.
        Cipher serverCipher = Cipher.getInstance("AES/CTS/NoPadding");
        serverCipher.init(Cipher.DECRYPT_MODE, clientAesKey, aesIv);

        return serverCipher.doFinal(cipherText);
    }


    byte[] concatenateBytes(byte[] array1, byte[] array2) {
        byte[] concatenatedBytes = new byte[array1.length + array2.length];

        for (int i = 0; i < array1.length; i++) {
            concatenatedBytes[i] = array1[i];
        }

        for (int j = array1.length; j < concatenatedBytes.length; j++) {
            concatenatedBytes[j] = array2[j - array1.length];
        }

        return concatenatedBytes;
    }
}
