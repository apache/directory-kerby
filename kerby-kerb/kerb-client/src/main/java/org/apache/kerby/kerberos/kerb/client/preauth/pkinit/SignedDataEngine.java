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


import org.apache.kerby.kerberos.kerb.spec.pa.pkinit.AuthPack;
import org.apache.kerby.kerberos.kerb.spec.pa.pkinit.KdcDHKeyInfo;
import org.apache.kerby.kerberos.kerb.spec.pa.pkinit.ReplyKeyPack;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSSignedGenerator;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.Certificate;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;


/**
 * Encapsulates working with PKINIT signed data structures.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 * @version $Rev$, $Date$
 */
public class SignedDataEngine {
    private static final String ID_PKINIT_AUTHDATA = "1.3.6.1.5.2.3.1";
    private static final String ID_PKINIT_DHKEYDATA = "1.3.6.1.5.2.3.2";
    private static final String ID_PKINIT_RKEYDATA = "1.3.6.1.5.2.3.3";

    /**
     * Uses a private key to sign data in a CMS SignedData structure and returns
     * the encoded CMS SignedData as bytes.
     * <p/>
     * 'signedAuthPack' contains a CMS type ContentInfo encoded according to [RFC3852].
     * The contentType field of the type ContentInfo is id-signedData (1.2.840.113549.1.7.2),
     * and the content field is a SignedData.
     * <p/>
     * The eContentType field for the type SignedData is id-pkinit-authData (1.3.6.1.5.2.3.1),
     * and the eContent field contains the DER encoding of the type AuthPack.
     *
     * @param privateKey
     * @param certificate
     * @param authPack
     * @return The CMS SignedData bytes.
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     * @throws InvalidAlgorithmParameterException
     * @throws CertStoreException
     * @throws CMSException
     * @throws IOException
     */
    public static byte[] getSignedAuthPack(PrivateKey privateKey, X509Certificate certificate, AuthPack authPack)
            throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException,
            CertStoreException, CMSException, IOException {
        return getSignedData(privateKey, certificate, authPack.encode(), ID_PKINIT_AUTHDATA);
    }


    /**
     * Uses a private key to sign data in a CMS SignedData structure and returns
     * the encoded CMS SignedData as bytes.
     * <p/>
     * 'dhSignedData' contains a CMS type ContentInfo encoded according to [RFC3852].
     * The contentType field of the type ContentInfo is id-signedData (1.2.840.113549.1.7.2),
     * and the content field is a SignedData.
     * <p/>
     * The eContentType field for the type SignedData is id-pkinit-DHKeyData (1.3.6.1.5.2.3.2),
     * and the eContent field contains the DER encoding of the type KDCDHKeyInfo.
     *
     * @param privateKey
     * @param certificate
     * @param kdcDhKeyInfo
     * @return The CMS SignedData bytes.
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     * @throws InvalidAlgorithmParameterException
     * @throws CertStoreException
     * @throws CMSException
     * @throws IOException
     */
    public static byte[] getSignedKdcDhKeyInfo(PrivateKey privateKey, X509Certificate certificate,
                                               KdcDHKeyInfo kdcDhKeyInfo)
            throws NoSuchAlgorithmException, NoSuchProviderException,
            InvalidAlgorithmParameterException, CertStoreException, CMSException, IOException {
        return getSignedData(privateKey, certificate, kdcDhKeyInfo.encode(), ID_PKINIT_DHKEYDATA);
    }


    /**
     * Uses a private key to sign data in a CMS SignedData structure and returns
     * the encoded CMS SignedData as bytes.
     * <p/>
     * Selected when public key encryption is used.
     * <p/>
     * The eContentType field for the inner type SignedData (when unencrypted) is
     * id-pkinit-rkeyData (1.3.6.1.5.2.3.3) and the eContent field contains the
     * DER encoding of the type ReplyKeyPack.
     *
     * @param privateKey
     * @param certificate
     * @param replyKeyPack
     * @return The CMS SignedData bytes.
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     * @throws InvalidAlgorithmParameterException
     * @throws CertStoreException
     * @throws CMSException
     * @throws IOException
     */
    public static byte[] getSignedReplyKeyPack(PrivateKey privateKey, X509Certificate certificate,
                                               ReplyKeyPack replyKeyPack)
            throws NoSuchAlgorithmException, NoSuchProviderException,
            InvalidAlgorithmParameterException, CertStoreException, CMSException, IOException {
        return getSignedData(privateKey, certificate, replyKeyPack.encode(), ID_PKINIT_RKEYDATA);
    }


    static byte[] getSignedData(PrivateKey privateKey, X509Certificate certificate, byte[] dataToSign,
                                String eContentType) throws NoSuchAlgorithmException, NoSuchProviderException,
            InvalidAlgorithmParameterException, CertStoreException, CMSException, IOException {
        CMSSignedDataGenerator signedGenerator = new CMSSignedDataGenerator();
        signedGenerator.addSigner(privateKey, certificate, CMSSignedGenerator.DIGEST_SHA1);

        Collection<X509Certificate> certList = Collections.singletonList(certificate);

        CertStore certStore = CertStore.getInstance("Collection", new CollectionCertStoreParameters(certList), "BC");
        signedGenerator.addCertificatesAndCRLs(certStore);

        CMSProcessableByteArray cmsByteArray = new CMSProcessableByteArray(dataToSign);
        CMSSignedData signedData = signedGenerator.generate(eContentType, cmsByteArray, true, "BC");

        return signedData.getEncoded();
    }


    /**
     * Validates a CMS SignedData using the public key corresponding to the private
     * key used to sign the structure.
     *
     * @param signedData
     * @return true if the signature is valid.
     * @throws Exception
     */
    @SuppressWarnings("unchecked")
    public static boolean validateSignedData(CMSSignedData signedData) throws Exception {
        CertStore certs = signedData.getCertificatesAndCRLs("Collection", "BC");

        SignerInformationStore signers = signedData.getSignerInfos();
        Collection<SignerInformation> c = signers.getSigners();
        Iterator<SignerInformation> it = c.iterator();

        while (it.hasNext()) {
            final SignerInformation signer = it.next();

            Collection<? extends Certificate> certCollection = certs.getCertificates(signer.getSID());
            /*Collection<? extends Certificate> certCollection = certs
                .getCertificates(new CertSelector() {
                    @Override
                    public boolean match(Certificate cert) {
                        return false; // check cert and signer
                    }
                });
            */
            Iterator<? extends Certificate> certIt = certCollection.iterator();

            X509Certificate cert = (X509Certificate) certIt.next();

            if (signer.verify(cert.getPublicKey(), "BC")) {
                return true;
            }
        }

        return false;
    }
}
