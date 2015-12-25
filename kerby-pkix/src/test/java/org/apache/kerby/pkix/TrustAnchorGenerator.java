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

import org.bouncycastle.asn1.DERBMPString;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.jce.interfaces.PKCS12BagAttributeCarrier;
import org.bouncycastle.x509.X509V3CertificateGenerator;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;


/**
 * Generates an X.509 "trust anchor" certificate programmatically.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 * @version $Rev$, $Date$
 */
public class TrustAnchorGenerator {
    /**
     * Create CA certificate.
     *
     * @param publicKey
     * @param privateKey
     * @param dn
     * @param validityDays
     * @param friendlyName
     * @return The certificate.
     * @throws InvalidKeyException
     * @throws SecurityException
     * @throws SignatureException
     * @throws NoSuchAlgorithmException
     * @throws DataLengthException
     * @throws CertificateException
     */
    public static X509Certificate generate(PublicKey publicKey, PrivateKey privateKey,
                                           String dn, int validityDays, String friendlyName)
            throws InvalidKeyException, SecurityException, SignatureException,
            NoSuchAlgorithmException, DataLengthException, CertificateException {
        X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();

        // Set certificate attributes.
        certGen.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));

        X509Principal x509Principal = new X509Principal(dn);
        certGen.setIssuerDN(x509Principal);
        certGen.setSubjectDN(x509Principal);

        certGen.setNotBefore(new Date());

        Calendar expiry = Calendar.getInstance();
        expiry.add(Calendar.DAY_OF_YEAR, validityDays);

        certGen.setNotAfter(expiry.getTime());

        certGen.setPublicKey(publicKey);
        certGen.setSignatureAlgorithm("SHA1WithRSAEncryption");

        certGen
                .addExtension(X509Extensions.SubjectKeyIdentifier, false,
                        new SubjectKeyIdentifier(getDigest(SubjectPublicKeyInfo.getInstance(publicKey.getEncoded()))));

        certGen.addExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(1));

        certGen.addExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.digitalSignature
                | KeyUsage.keyCertSign | KeyUsage.cRLSign));

        X509Certificate cert = certGen.generate(privateKey);

        PKCS12BagAttributeCarrier bagAttr = (PKCS12BagAttributeCarrier) cert;

        bagAttr.setBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_friendlyName, new DERBMPString(friendlyName));
        bagAttr.setBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_localKeyId,
                new SubjectKeyIdentifier(getDigest(SubjectPublicKeyInfo.getInstance(publicKey.getEncoded()))));

        return cert;
    }

    private static byte[] getDigest(SubjectPublicKeyInfo spki) {
        Digest digest = new SHA1Digest();
        byte[] resBuf = new byte[digest.getDigestSize()];

        byte[] bytes = spki.getPublicKeyData().getBytes();
        digest.update(bytes, 0, bytes.length);
        digest.doFinal(resBuf, 0);
        return resBuf;
    }
}
