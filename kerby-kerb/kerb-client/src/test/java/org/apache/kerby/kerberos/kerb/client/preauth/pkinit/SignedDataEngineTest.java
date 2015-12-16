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
package org.apache.kerby.kerberos.kerb.client.preauth.pkinit;


import junit.framework.TestCase;
import org.apache.kerby.kerberos.kerb.client.preauth.pkinit.certs.CertificateChainFactory;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateCrtKey;

/**
 * Tests the use of {@link CMSSignedData}.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 * @version $Rev$, $Date$
 */
public class SignedDataEngineTest extends TestCase {
    /**
     * The log for this class.
     */
    private static final Logger LOG = LoggerFactory.getLogger(SignedDataEngineTest.class);

    private static final String ID_DATA = "1.2.840.113549.1.7.1";

    /**
     * Certificate used to verify the signature.
     */
    private X509Certificate certificate;

    /**
     * Private key used to sign the data.
     */
    private PrivateKey privateKey;


    public void setUp() throws Exception {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }

        //getCaFromFile( "/tmp/testCa.p12", "password", "Test CA" );
        getCaFromFactory();
    }


    /**
     * Tests that signed data signature validation works.
     *
     * @throws Exception
     */
    public void testSignedData() throws Exception {
        byte[] data = "Hello".getBytes();

        byte[] signedDataBytes = SignedDataEngine.getSignedData(privateKey, certificate, data, ID_DATA);

        CMSSignedData signedData = new CMSSignedData(signedDataBytes);

        assertTrue(SignedDataEngine.validateSignedData(signedData));
    }


    void getCaFromFactory() throws Exception {
        X509Certificate[] clientChain = CertificateChainFactory.getClientChain();
        certificate = clientChain[0];

        privateKey = CertificateChainFactory.getClientPrivateKey();
    }


    void getCaFromFile(String caFile, String caPassword, String caAlias) throws KeyStoreException,
            NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException,
            UnrecoverableKeyException, InvalidKeyException, SignatureException, NoSuchProviderException {
        // Open the keystore.
        KeyStore caKs = KeyStore.getInstance("PKCS12");
        caKs.load(new FileInputStream(new File(caFile)), caPassword.toCharArray());

        // Load the private key from the keystore.
        privateKey = (RSAPrivateCrtKey) caKs.getKey(caAlias, caPassword.toCharArray());

        if (privateKey == null) {
            throw new IllegalStateException("Got null key from keystore!");
        }

        // Load the certificate from the keystore.
        certificate = (X509Certificate) caKs.getCertificate(caAlias);

        if (certificate == null) {
            throw new IllegalStateException("Got null cert from keystore!");
        }

        LOG.debug("Successfully loaded CA key and certificate. CA DN is '{}'.", certificate.getSubjectDN().getName());

        // Verify.
        certificate.verify(certificate.getPublicKey());
        LOG.debug("Successfully verified CA certificate with its own public key.");
    }
}
