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
package org.apache.kerby.kerberos.kerb.client.preauth.pkinit.certs;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DERBMPString;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.jce.PrincipalUtil;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.jce.interfaces.PKCS12BagAttributeCarrier;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.bouncycastle.x509.extension.AuthorityKeyIdentifierStructure;
import org.bouncycastle.x509.extension.SubjectKeyIdentifierStructure;

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
 * Generates an X.509 "end entity" certificate programmatically.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 * @version $Rev$, $Date$
 */
@SuppressWarnings({"PMD.UnusedPrivateField"})
public class EndEntityGenerator {
    /**
     * id-pkinit-san OBJECT IDENTIFIER ::=
     * { iso(1) org(3) dod(6) internet(1) security(5) kerberosv5(2) x509SanAN (2) }
     */
    private static final DERObjectIdentifier ID_PKINIT_SAN = new DERObjectIdentifier("1.3.6.1.5.2.2");

    /**
     * id-pkinit-KPClientAuth OBJECT IDENTIFIER ::=
     * { iso(1) org(3) dod(6) internet(1) security(5) kerberosv5(2) pkinit(3) keyPurposeClientAuth(4) }
     * -- PKINIT client authentication.
     * -- Key usage bits that MUST be consistent:
     * -- digitalSignature.
     */
    private static final DERObjectIdentifier ID_PKINIT_KPCLIENTAUTH = new DERObjectIdentifier("1.3.6.1.5.2.3.4");

    /**
     * id-pkinit-KPKdc OBJECT IDENTIFIER ::=
     * { iso(1) org(3) dod(6) internet(1) security(5) kerberosv5(2) pkinit(3) keyPurposeKdc(5) }
     * -- Signing KDC responses.
     * -- Key usage bits that MUST be consistent:
     * -- digitalSignature.
     */
    private static final DERObjectIdentifier ID_PKINIT_KPKDC = new DERObjectIdentifier("1.3.6.1.5.2.3.5");

    private static final DERObjectIdentifier ID_MS_KP_SC_LOGON = new DERObjectIdentifier("1.3.6.1.4.1.311.20.2.2");

    private static final DERObjectIdentifier ID_MS_SAN_SC_LOGON_UPN = new DERObjectIdentifier("1.3.6.1.4.1.311.20.2.3");


    /**
     * Generate certificate.
     *
     * @param issuerCert
     * @param issuerPrivateKey
     * @param publicKey
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
    public static X509Certificate generate(X509Certificate issuerCert, PrivateKey issuerPrivateKey,
                                           PublicKey publicKey, String dn, int validityDays,
                                           String friendlyName)
            throws InvalidKeyException, SecurityException, SignatureException,
            NoSuchAlgorithmException, DataLengthException, CertificateException {
        X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();

        // Set certificate attributes.
        certGen.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));

        certGen.setIssuerDN(PrincipalUtil.getSubjectX509Principal(issuerCert));
        certGen.setSubjectDN(new X509Principal(dn));

        certGen.setNotBefore(new Date());

        Calendar expiry = Calendar.getInstance();
        expiry.add(Calendar.DAY_OF_YEAR, validityDays);

        certGen.setNotAfter(expiry.getTime());

        certGen.setPublicKey(publicKey);
        certGen.setSignatureAlgorithm("SHA1WithRSAEncryption");

        certGen
                .addExtension(X509Extensions.SubjectKeyIdentifier, false,
                        new SubjectKeyIdentifierStructure(publicKey));

        // MAY set BasicConstraints=false or not at all.
        certGen.addExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(false));

        certGen.addExtension(X509Extensions.AuthorityKeyIdentifier, false,
                new AuthorityKeyIdentifierStructure(issuerCert));

        certGen.addExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.digitalSignature
                | KeyUsage.keyEncipherment | KeyUsage.dataEncipherment));

        ASN1EncodableVector keyPurposeVector = new ASN1EncodableVector();
        keyPurposeVector.add(KeyPurposeId.id_kp_smartcardlogon);
        //keyPurposeVector.add( KeyPurposeId.id_kp_serverAuth );
        DERSequence keyPurposeOids = new DERSequence(keyPurposeVector);

        // If critical, will throw unsupported EKU.
        certGen.addExtension(X509Extensions.ExtendedKeyUsage, false, keyPurposeOids);

        ASN1EncodableVector pkinitSanVector = new ASN1EncodableVector();
        pkinitSanVector.add(ID_PKINIT_SAN);
        pkinitSanVector.add(new DERTaggedObject(0, new DERSequence()));
        DERSequence pkinitSan = new DERSequence(pkinitSanVector);

        String dnsName = "localhost";

        ASN1EncodableVector sanVector = new ASN1EncodableVector();
        sanVector.add(new GeneralName(GeneralName.otherName, pkinitSan));
        sanVector.add(new GeneralName(GeneralName.dNSName, dnsName));
        DERSequence san = new DERSequence(sanVector);

        GeneralNames sanGeneralNames = new GeneralNames(san);

        certGen.addExtension(X509Extensions.SubjectAlternativeName, true, sanGeneralNames);

        /*
         * The KDC MAY require the presence of an Extended Key Usage (EKU) KeyPurposeId
         * [RFC3280] id-pkinit-KPClientAuth in the extensions field of the client's
         * X.509 certificate.
         */

        /*
         * The digitalSignature key usage bit [RFC3280] MUST be asserted when the
         * intended purpose of the client's X.509 certificate is restricted with
         * the id-pkinit-KPClientAuth EKU.
         */

        /*
         * KDCs implementing this requirement SHOULD also accept the EKU KeyPurposeId
         * id-ms-kp-sc-logon (1.3.6.1.4.1.311.20.2.2) as meeting the requirement, as
         * there are a large number of X.509 client certificates deployed for use
         * with PKINIT that have this EKU.
         */

        // KDC
        /*
         * In addition, unless the client can otherwise verify that the public key
         * used to verify the KDC's signature is bound to the KDC of the target realm,
         * the KDC's X.509 certificate MUST contain a Subject Alternative Name extension
         * [RFC3280] carrying an AnotherName whose type-id is id-pkinit-san (as defined
         * in Section 3.2.2) and whose value is a KRB5PrincipalName that matches the
         * name of the TGS of the target realm (as defined in Section 7.3 of [RFC4120]).
         */

        /*
         * Unless the client knows by some other means that the KDC certificate is
         * intended for a Kerberos KDC, the client MUST require that the KDC certificate
         * contains the EKU KeyPurposeId [RFC3280] id-pkinit-KPKdc.
         */

        /*
         * The digitalSignature key usage bit [RFC3280] MUST be asserted when the
         * intended purpose of the KDC's X.509 certificate is restricted with the
         * id-pkinit-KPKdc EKU.
         */

        /*
         * If the KDC certificate contains the Kerberos TGS name encoded as an id-pkinit-san
         * SAN, this certificate is certified by the issuing CA as a KDC certificate,
         * therefore the id-pkinit-KPKdc EKU is not required.
         */

        /*
         * KDC certificates issued by Windows 2000 Enterprise CAs contain a dNSName
         * SAN with the DNS name of the host running the KDC, and the id-kp-serverAuth
         * EKU [RFC3280].
         */

        /*
         * KDC certificates issued by Windows 2003 Enterprise CAs contain a dNSName
         * SAN with the DNS name of the host running the KDC, the id-kp-serverAuth
         * EKU, and the id-ms-kp-sc-logon EKU.
         */

        /*
         * RFC: KDC certificates with id-pkinit-san SAN as specified in this RFC.
         * 
         * MS:  dNSName SAN containing the domain name of the KDC
         *      id-pkinit-KPKdc EKU
         *      id-kp-serverAuth EKU.
         */

        /*
         * Client certificates accepted by Windows 2000 and Windows 2003 Server KDCs
         * must contain an id-ms-san-sc-logon-upn (1.3.6.1.4.1.311.20.2.3) SAN and
         * the id-ms-kp-sc-logon EKU.  The id-ms-san-sc-logon-upn SAN contains a
         * UTF8-encoded string whose value is that of the Directory Service attribute
         * UserPrincipalName of the client account object, and the purpose of including
         * the id-ms-san-sc-logon-upn SAN in the client certificate is to validate
         * the client mapping (in other words, the client's public key is bound to
         * the account that has this UserPrincipalName value).
         */

        X509Certificate cert = certGen.generate(issuerPrivateKey);

        PKCS12BagAttributeCarrier bagAttr = (PKCS12BagAttributeCarrier) cert;

        bagAttr.setBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_friendlyName, new DERBMPString(friendlyName));
        bagAttr.setBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_localKeyId, new SubjectKeyIdentifierStructure(
                publicKey));

        return cert;
    }
}
