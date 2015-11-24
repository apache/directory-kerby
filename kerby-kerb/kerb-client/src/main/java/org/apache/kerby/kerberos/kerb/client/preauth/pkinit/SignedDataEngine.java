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
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.Store;
import sun.security.pkcs.ContentInfo;
import sun.security.pkcs.PKCS7;
import sun.security.pkcs.SignerInfo;
import sun.security.util.DerValue;
import sun.security.util.ObjectIdentifier;
import sun.security.x509.AlgorithmId;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;


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
     * @throws OperatorCreationException
     * @throws CertificateEncodingException
     * @throws CMSException
     * @throws IOException
     */
    public static byte[] getSignedAuthPack(PrivateKey privateKey, X509Certificate certificate,
                                           AuthPack authPack)
            throws OperatorCreationException, CertificateEncodingException, CMSException, IOException {
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
     * @throws OperatorCreationException
     * @throws CertificateEncodingException
     * @throws CMSException
     * @throws IOException
     */
    public static byte[] getSignedKdcDhKeyInfo(PrivateKey privateKey, X509Certificate certificate,
                                               KdcDHKeyInfo kdcDhKeyInfo)
            throws OperatorCreationException, CertificateEncodingException, CMSException, IOException {
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
     * @throws OperatorCreationException
     * @throws CertificateEncodingException
     * @throws CMSException
     * @throws IOException
     */
    public static byte[] getSignedReplyKeyPack(PrivateKey privateKey, X509Certificate certificate,
                                               ReplyKeyPack replyKeyPack)
            throws OperatorCreationException, CertificateEncodingException, CMSException, IOException {
        return getSignedData(privateKey, certificate, replyKeyPack.encode(), ID_PKINIT_RKEYDATA);
    }


    static byte[] getSignedData(PrivateKey privateKey, X509Certificate certificate, byte[] dataToSign,
                                String eContentType) throws IOException, OperatorCreationException,
            CertificateEncodingException, CMSException {

        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }


        List certList = new ArrayList();
        certList.add(certificate);
        Store certs = new JcaCertStore(certList);

        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();

        gen.addSignerInfoGenerator(
                new JcaSimpleSignerInfoGeneratorBuilder()
                        .setProvider("BC")
                        .build("SHA1withRSA", privateKey, certificate));

        gen.addCertificates(certs);

        ASN1ObjectIdentifier asn1ObjectIdentifier = new ASN1ObjectIdentifier(eContentType);
        CMSTypedData msg = new CMSProcessableByteArray(asn1ObjectIdentifier, dataToSign);
        CMSSignedData s = gen.generate(msg, true);

        return s.getEncoded();
    }

    /**
     * Validates a CMS SignedData using the public key corresponding to the private
     * key used to sign the structure.
     *
     * @param s
     * @return true if the signature is valid.
     * @throws Exception
     */
    public static boolean validateSignedData(CMSSignedData s) throws Exception {

        Store certStore = s.getCertificates();
        Store crlStore = s.getCRLs();
        SignerInformationStore signers = s.getSignerInfos();

        Collection c = signers.getSigners();
        Iterator it = c.iterator();

        while (it.hasNext()) {
            SignerInformation signer = (SignerInformation) it.next();
            Collection certCollection = certStore.getMatches(signer.getSID());

            Iterator certIt = certCollection.iterator();
            X509CertificateHolder cert = (X509CertificateHolder) certIt.next();

            if (!signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(cert))) {
                return false;
            }
        }

        Collection certColl = certStore.getMatches(null);
        Collection crlColl = crlStore.getMatches(null);

        if (certColl.size() != s.getCertificates().getMatches(null).size()
                || crlColl.size() != s.getCRLs().getMatches(null).size()) {
            return false;
        }
        return true;
    }

    public static ContentInfo createContentInfo(byte[] data, ObjectIdentifier oid) {

        ContentInfo contentInfo = new ContentInfo(
                oid,
                new DerValue(DerValue.tag_OctetString, data));
        return contentInfo;
    }

    public static ByteArrayOutputStream cmsSignedDataCreate(AuthPack authPack,
                                                            X509Certificate certificate) throws IOException {

        ObjectIdentifier oid = new ObjectIdentifier(ID_PKINIT_AUTHDATA);
        ContentInfo contentInfo = createContentInfo(authPack.encode(), oid);

        X509Certificate[] certificates = {certificate};
        PKCS7 p7 = new PKCS7(new AlgorithmId[0], contentInfo, certificates, new SignerInfo[0]);
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        p7.encodeSignedData(bytes);
        return bytes;
    }

}
