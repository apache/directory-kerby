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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;

/**
 * Factory for dynamically generating certificate chains.
 */
public class CertificateChainFactory {
    private static final Logger LOG = LoggerFactory.getLogger(CertificateChainFactory.class);

    private static int trustAnchorLevel = 2;

    private static int intermediateLevel = 1;

    private static int endEntityLevel = 0;

    private static SecureRandom secureRandom = new SecureRandom();

    private static String container =
            "C=US, ST=Maryland, L=Forest Hill, O=Apache Software Foundation, OU=Apache Directory, CN=";

    private static boolean isGenerated = false;

    private static boolean isInitialized = false;

    private static X509Certificate[] clientChain;

    private static X509Certificate[] kdcChain;

    private static PrivateKey clientPrivateKey;

    private static PrivateKey kdcPrivateKey;


    public static X509Certificate[] getKdcChain() throws Exception {
        init();

        return kdcChain;
    }


    public static X509Certificate[] getClientChain() throws Exception {
        init();

        return clientChain;
    }


    public static PrivateKey getKdcPrivateKey() throws Exception {
        init();

        return kdcPrivateKey;
    }


    public static PrivateKey getClientPrivateKey() throws Exception {
        init();

        return clientPrivateKey;
    }


    private static void init() throws Exception {
        if (!isInitialized) {
            initClientChain();
            initKdcChain();
            isInitialized = true;
        }
    }


    private static void initClientChain() throws Exception {
        // Make trust anchor.
        String friendlyName = "Test Root CA";
        String dn = container + friendlyName;
        int validityDays = 730;

        KeyPair keyPair = getKeyPair(trustAnchorLevel);
        PrivateKey trustAnchorPrivateKey = keyPair.getPrivate();
        PublicKey trustAnchorPublicKey = keyPair.getPublic();

        X509Certificate trustAnchorCert = TrustAnchorGenerator.generate(trustAnchorPublicKey, trustAnchorPrivateKey,
            dn, validityDays, friendlyName);

        trustAnchorCert.checkValidity();
        trustAnchorCert.verify(trustAnchorPublicKey);

        LOG.debug("Generated cert for friendly name '{}', valid for {} days.", friendlyName, validityDays);

        // Make intermediate client CA.
        friendlyName = "Client Test CA 1";
        dn = container + friendlyName;
        validityDays = 365;

        keyPair = getKeyPair(intermediateLevel);
        PrivateKey clientCaPrivateKey = keyPair.getPrivate();
        PublicKey clientCaPublicKey = keyPair.getPublic();

        X509Certificate clientCaCert = IntermediateCaGenerator.generate(trustAnchorCert, trustAnchorPrivateKey,
            clientCaPublicKey, dn, validityDays, friendlyName);

        clientCaCert.checkValidity();
        clientCaCert.verify(trustAnchorPublicKey);

        LOG.debug("Generated cert for friendly name '{}', valid for {} days.", friendlyName, validityDays);

        // Make client certificate.
        friendlyName = "hnelson@EXAMPLE.COM UPN";
        dn = container + friendlyName;
        validityDays = 30;

        keyPair = getKeyPair(endEntityLevel);
        clientPrivateKey = keyPair.getPrivate();
        PublicKey clientPublicKey = keyPair.getPublic();

        X509Certificate clientCert = EndEntityGenerator.generate(clientCaCert, clientCaPrivateKey, clientPublicKey,
            dn, validityDays, friendlyName);

        clientCert.checkValidity();
        clientCert.verify(clientCaPublicKey);

        LOG.debug("Generated cert for friendly name '{}', valid for {} days.", friendlyName, validityDays);

        // Build client chain.
        clientChain = new X509Certificate[3];

        clientChain[2] = trustAnchorCert;
        clientChain[1] = clientCaCert;
        clientChain[0] = clientCert;
    }


    private static void initKdcChain() throws Exception {
        // Make trust anchor.
        String friendlyName = "Test Root CA";
        String dn = container + friendlyName;
        int validityDays = 730;

        KeyPair keyPair = getKeyPair(trustAnchorLevel);
        PrivateKey trustAnchorPrivateKey = keyPair.getPrivate();
        PublicKey trustAnchorPublicKey = keyPair.getPublic();

        X509Certificate trustAnchorCert = TrustAnchorGenerator.generate(trustAnchorPublicKey, trustAnchorPrivateKey,
                dn, validityDays, friendlyName);

        trustAnchorCert.checkValidity();
        trustAnchorCert.verify(trustAnchorPublicKey);

        LOG.debug("Generated cert for friendly name '{}', valid for {} days.", friendlyName, validityDays);

        // Make intermediate KDC CA.
        friendlyName = "KDC Test CA 1";
        dn = container + friendlyName;
        validityDays = 365;

        keyPair = getKeyPair(intermediateLevel);
        PrivateKey kdcCaPrivateKey = keyPair.getPrivate();
        PublicKey kdcCaPublicKey = keyPair.getPublic();

        X509Certificate kdcCaCert = IntermediateCaGenerator.generate(trustAnchorCert, trustAnchorPrivateKey,
                kdcCaPublicKey, dn, validityDays, friendlyName);

        kdcCaCert.checkValidity();
        kdcCaCert.verify(trustAnchorPublicKey);

        LOG.debug("Generated cert for friendly name '{}', valid for {} days.", friendlyName, validityDays);

        // Make KDC certificate.
        friendlyName = "krbtgt/EXAMPLE.COM@EXAMPLE.COM KDC";
        dn = container + friendlyName;
        validityDays = 30;

        keyPair = getKeyPair(endEntityLevel);
        kdcPrivateKey = keyPair.getPrivate();
        PublicKey kdcPublicKey = keyPair.getPublic();

        X509Certificate kdcCert = EndEntityGenerator.generate(kdcCaCert, kdcCaPrivateKey, kdcPublicKey, dn,
                validityDays, friendlyName);

        kdcCert.checkValidity();
        kdcCert.verify(kdcCaPublicKey);

        LOG.debug("Generated cert for friendly name '{}', valid for {} days.", friendlyName, validityDays);

        // Build KDC chain.
        kdcChain = new X509Certificate[3];

        kdcChain[2] = trustAnchorCert;
        kdcChain[1] = kdcCaCert;
        kdcChain[0] = kdcCert;
    }


    /**
     * Get a key pair for the new certificate.  Depending on the static constant
     * 'isGenerated', these key pairs can be dynamically generated (slower) or
     * built from static constant values (faster).
     *
     * @param level
     * @return The key pair.
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     * @throws InvalidKeySpecException
     */
    private static KeyPair getKeyPair(int level) throws NoSuchAlgorithmException, NoSuchProviderException,
            InvalidKeySpecException {
        if (isGenerated) {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(1024, secureRandom);
            return keyGen.generateKeyPair();
        } else {
            return getStaticKeyPair(level);
        }
    }


    /**
     * Get a key pair generated using static key values.  This is much faster than
     * dynamically generating key values.
     *
     * @param level
     * @return The static key pair.
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     * @throws InvalidKeySpecException
     */
    private static KeyPair getStaticKeyPair(int level) throws NoSuchAlgorithmException, NoSuchProviderException,
            InvalidKeySpecException {
        KeyFactory keyFactory = KeyFactory.getInstance("RSA", "BC");

        switch (level) {
            case 2:
                PrivateKey caPrivKey = keyFactory.generatePrivate(KeyPairSpec.caPrivKeySpec);
                PublicKey caPubKey = keyFactory.generatePublic(KeyPairSpec.caPubKeySpec);
                return new KeyPair(caPubKey, caPrivKey);
            case 1:
                PrivateKey intPrivKey = keyFactory.generatePrivate(KeyPairSpec.intPrivKeySpec);
                PublicKey intPubKey = keyFactory.generatePublic(KeyPairSpec.intPubKeySpec);
                return new KeyPair(intPubKey, intPrivKey);
            case 0:
            default:
                PrivateKey privKey = keyFactory.generatePrivate(KeyPairSpec.privKeySpec);
                PublicKey pubKey = keyFactory.generatePublic(KeyPairSpec.pubKeySpec);
                return new KeyPair(pubKey, privKey);
        }
    }
}
