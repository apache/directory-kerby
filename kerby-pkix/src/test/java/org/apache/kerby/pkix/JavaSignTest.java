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
package org.apache.kerby.pkix;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;

/**
 * This is a JAVA sign and verify test to serve as a good sample.
 */
public class JavaSignTest {

    static class SignAlgorithm {
        String algo;
        String keyType;

        SignAlgorithm(String algo, String keyType) {
            this.algo = algo;
            this.keyType = keyType;
        }
    }

    static final SignAlgorithm[] ALGORITHMS = {
        new SignAlgorithm("DSA", "DSA"),
        new SignAlgorithm("SHA1withDSA", "DSA"),
        new SignAlgorithm("SHA1withRSA", "RSA"),
        new SignAlgorithm("SHA256withRSA", "RSA"),
        new SignAlgorithm("SHA384withRSA", "RSA"),
        new SignAlgorithm("SHA512withRSA", "RSA"),
        new SignAlgorithm("MD5withRSA", "RSA"),
        new SignAlgorithm("MD5andSHA1withRSA", "RSA"),
        new SignAlgorithm("SHA256withRSA", "RSA")
    };

    static byte[] signData(byte[] dataToSign, KeyPair keyPair,
                           SignAlgorithm sa) throws Exception {
        byte[] signResult;
        Signature signer = Signature.getInstance(sa.algo);
        signer.initSign(keyPair.getPrivate());
        signer.update(dataToSign);
        signResult = signer.sign();

        return signResult;
    }

    static boolean verifyData(byte[] dataToVerify, byte[] signature,
                              KeyPair keyPair, SignAlgorithm sa) throws Exception {
        boolean verifyResult;
        Signature verifier = Signature.getInstance(sa.algo);
        verifier.initVerify(keyPair.getPublic());
        verifier.update(dataToVerify);
        verifyResult = verifier.verify(signature);

        return verifyResult;
    }

    public static void main(String[] args) throws Exception {
        for (SignAlgorithm sa : ALGORITHMS) {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance(sa.keyType);
            keyGen.initialize(1024);
            KeyPair keyPair = keyGen.generateKeyPair();

            byte[] testMessage = "Hello, Kerby!!".getBytes();
            byte[] signature = signData(testMessage, keyPair, sa);
            boolean isOk = verifyData(testMessage, signature, keyPair, sa);
            if (!isOk) {
                throw new RuntimeException("Failed");
            }
        }
    }
}
