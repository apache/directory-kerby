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
package org.apache.kerby.kerberos.kerb.crypto.dh;

import org.apache.kerby.kerberos.kerb.crypto.EncTypeHandler;
import org.apache.kerby.kerberos.kerb.crypto.EncryptionHandler;
import org.apache.kerby.kerberos.kerb.type.base.EncryptionKey;
import org.apache.kerby.kerberos.kerb.type.base.EncryptionType;
import org.apache.kerby.kerberos.kerb.type.base.KeyUsage;

import javax.crypto.KeyAgreement;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;


/**
 * The server-side of Diffie-Hellman key agreement for Kerberos PKINIT.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class DiffieHellmanServer {

    private KeyAgreement serverKeyAgree;
    private EncryptionKey serverKey;

    public PublicKey initAndDoPhase(byte[] clientPubKeyEnc) throws Exception {
        /*
         * The server has received the client's public key in encoded format.  The
         * server instantiates a DH public key from the encoded key material.
         */
        KeyFactory serverKeyFac = KeyFactory.getInstance("DH");
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(clientPubKeyEnc);
        PublicKey clientPubKey = serverKeyFac.generatePublic(x509KeySpec);

        /*
         * The server gets the DH parameters associated with the client's public
         * key.  The server must use the same parameters when it generates its own key pair.
         */
        DHParameterSpec dhParamSpec = ((DHPublicKey) clientPubKey).getParams();

        // The server creates its own DH key pair.
        KeyPairGenerator serverKpairGen = KeyPairGenerator.getInstance("DH");
        serverKpairGen.initialize(dhParamSpec);
        KeyPair serverKpair = serverKpairGen.generateKeyPair();

        // The server creates and initializes its DH KeyAgreement object.
        serverKeyAgree = KeyAgreement.getInstance("DH");
        serverKeyAgree.init(serverKpair.getPrivate());

        /*
         * The server uses the client's public key for the only phase of its
         * side of the DH protocol.
         */
        serverKeyAgree.doPhase(clientPubKey, true);

        // The server encodes its public key, and sends it over to the client.
        return serverKpair.getPublic();
    }

    public EncryptionKey generateKey(byte[] clientDhNonce, byte[] serverDhNonce, EncryptionType type) {
        // ZZ length will be same as public key.
        byte[] dhSharedSecret = serverKeyAgree.generateSecret();
        byte[] x = dhSharedSecret;

        if (clientDhNonce != null && clientDhNonce.length > 0
                && serverDhNonce != null && serverDhNonce.length > 0) {
            x = concatenateBytes(dhSharedSecret, clientDhNonce);
            x = concatenateBytes(x, serverDhNonce);
        }

        byte[] secret = OctetString2Key.kTruncate(dhSharedSecret.length, x);
        serverKey = new EncryptionKey(type, secret);

        return serverKey;
    }

    /**
     * Encrypt
     *
     * @param clearText The clear test
     * @return The cipher text.
     * @throws Exception e
     */
    public byte[] encrypt(byte[] clearText, KeyUsage usage) throws Exception {
        // Use the secret key to encrypt/decrypt data.
        EncTypeHandler encType = EncryptionHandler.getEncHandler(serverKey.getKeyType());
        return encType.encrypt(clearText, serverKey.getKeyData(), usage.getValue());
    }

    private byte[] concatenateBytes(byte[] array1, byte[] array2) {
        byte[] concatenatedBytes = new byte[array1.length + array2.length];

        System.arraycopy(array1, 0, concatenatedBytes, 0, array1.length);

        for (int j = array1.length; j < concatenatedBytes.length; j++) {
            concatenatedBytes[j] = array2[j - array1.length];
        }

        return concatenatedBytes;
    }
}
