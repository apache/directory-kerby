/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 * <p/>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p/>
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.kerby.kerberos.kerb.preauth.pkinit;

import org.apache.kerby.asn1.type.Asn1ObjectIdentifier;
import org.apache.kerby.cms.type.CertificateSet;
import org.apache.kerby.cms.type.DigestAlgorithmIdentifiers;
import org.apache.kerby.cms.type.EncapsulatedContentInfo;
import org.apache.kerby.cms.type.RevocationInfoChoices;
import org.apache.kerby.cms.type.SignedContentInfo;
import org.apache.kerby.cms.type.SignedData;
import org.apache.kerby.cms.type.SignerInfos;
import org.apache.kerby.kerberos.kerb.KrbCodec;
import org.apache.kerby.kerberos.kerb.KrbErrorCode;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.type.base.PrincipalName;
import org.apache.kerby.util.HexUtil;
import org.apache.kerby.x509.type.Certificate;
import org.apache.kerby.x509.type.DhParameter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPublicKeySpec;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
  * Ref. pkinit_crypto_openssl.c in MIT krb5 project.
  */
public class PkinitCrypto {

    private static final Logger LOG = LoggerFactory.getLogger(PkinitCrypto.class);

    /**
     * Verify CMS Signed Data
     * @param cmsMsgType The CMS message type
     * @param signedData The signed data
     * @throws KrbException e
     */
    public static void verifyCmsSignedData(CmsMessageType cmsMsgType, SignedData signedData)
            throws KrbException {
        String oid = pkinitType2OID(cmsMsgType);
        if (oid == null) {
            throw new KrbException("Can't get the right oid ");
        }

        String etype = signedData.getEncapContentInfo().getContentType();
        if (oid.equals(etype)) {
            LOG.info("CMS Verification successful");
        } else {
            LOG.error("Wrong oid in eContentType");
            throw new KrbException(KrbErrorCode.KDC_ERR_PREAUTH_FAILED, "Wrong oid in eContentType");
        }
    }

    /**
     * Change the CMS message type to oid
     * @param cmsMsgType The CMS message type
     * @return oid
     */
    public static String pkinitType2OID(CmsMessageType cmsMsgType) {
        switch (cmsMsgType) {
            case UNKNOWN:
                return null;
            case CMS_SIGN_CLIENT:
                return PkinitPlgCryptoContext.getIdPkinitAuthDataOID();
            case CMS_SIGN_SERVER:
                return PkinitPlgCryptoContext.getIdPkinitDHKeyDataOID();
            case CMS_ENVEL_SERVER:
                return PkinitPlgCryptoContext.getIdPkinitRkeyDataOID();
            default:
                return null;
        }
    }

    /**
     * KDC check the key parameter
     * @param pluginOpts The PluginOpts
     * @param cryptoctx The PkinitPlgCryptoContext
     * @param dhParameter The DhParameter
     * @throws KrbException e
     */
    public static void serverCheckDH(PluginOpts pluginOpts, PkinitPlgCryptoContext cryptoctx,
                                     DhParameter dhParameter) throws KrbException {
         /* KDC SHOULD check to see if the key parameters satisfy its policy */
        int dhPrimeBits = dhParameter.getP().bitLength();
        if (dhPrimeBits < pluginOpts.dhMinBits) {
            String errMsg = "client sent dh params with " + dhPrimeBits
                    + "bits, we require " + pluginOpts.dhMinBits;
            LOG.error(errMsg);
            throw new KrbException(KrbErrorCode.KDC_ERR_DH_KEY_PARAMETERS_NOT_ACCEPTED, errMsg);
        }
        if (!checkDHWellknown(cryptoctx, dhParameter, dhPrimeBits)) {
            throw new KrbException(KrbErrorCode.KDC_ERR_DH_KEY_PARAMETERS_NOT_ACCEPTED);
        }
    }

    /**
     * Check DH wellknown
     * @param cryptoctx The PkinitPlgCryptoContext
     * @param dhParameter The DhParameter
     * @param dhPrimeBits The dh prime bits
     * @return boolean
     * @throws KrbException e
     */
    public static boolean checkDHWellknown(PkinitPlgCryptoContext cryptoctx,
                                           DhParameter dhParameter, int dhPrimeBits) throws KrbException {
        boolean valid = false;
        switch (dhPrimeBits) {
            case 1024:
                /* Oakley MODP group 2 */
            case 2048:
                /* Oakley MODP group 14 */
            case 4096:
               /* Oakley MODP group 16 */
                valid = pkinitCheckDhParams(cryptoctx.createDHParameterSpec(dhPrimeBits), dhParameter);
                break;
            default:
                break;
        }
        return valid;
    }

    /**
     * Check parameters against a well-known DH group
     *
     * @param dh1 The DHParameterSpec
     * @param dh2 The DhParameter
     */
    public static boolean pkinitCheckDhParams(DHParameterSpec dh1, DhParameter dh2) {

        if (!dh1.getP().equals(dh2.getP())) {
            LOG.error("p is not well-known group dhparameter");
            return false;
        }
        if (!dh1.getG().equals(dh2.getG())) {
            LOG.error("bad g dhparameter");
            return false;
        }
        LOG.info("Good dhparams", dh1.getP().bitLength());
        return true;
    }

    /**
     * Create DH public key
     *
     * @param p The prime modulus
     * @param g The base generator
     * @param y The public value
     * @return  DHPublicKey
     */
    public static DHPublicKey createDHPublicKey(BigInteger p, BigInteger g, BigInteger y) {
        DHPublicKeySpec dhPublicKeySpec = new DHPublicKeySpec(y, p, g);

        KeyFactory keyFactory = null;
        try {
            keyFactory = KeyFactory.getInstance("DH");
        } catch (NoSuchAlgorithmException e) {
            LOG.error("Fail to get dh instance. " + e);
        }
        DHPublicKey dhPublicKey = null;
        try {
            if (keyFactory != null) {
                dhPublicKey = (DHPublicKey) keyFactory.generatePublic(dhPublicKeySpec);
            }
        } catch (InvalidKeySpecException e) {
            LOG.error("Fail to generate public key. " + e);
        }
        return dhPublicKey;
    }

    /**
     * RFC4556: The contentType field of the type ContentInfo
     * is id-signedData (1.2.840.113549.1.7.2),
     * and the content field is a SignedData.
     * The eContentType field for the type SignedData is
     * id-pkinit-authData (1.3.6.1.5.2.3.1), and the
     * eContent field contains the DER encoding of the
     * type AuthPack.
     *
     * @param data The data
     * @param oid The oid for eContentType
     * @param version The SignedData version
     * @param digestAlgorithmIdentifiers The digest algorithmIdentifiers
     * @param certificateSet The certificate set
     * @param crls The revocation info choices
     * @param signerInfos The signerInfos
     * @return The encoded signed data bytes
     * @throws KrbException e
     */
    public static byte[] cmsSignedDataCreate(byte[] data, String oid, int version,
                                             DigestAlgorithmIdentifiers digestAlgorithmIdentifiers,
                                             CertificateSet certificateSet,
                                             RevocationInfoChoices crls, SignerInfos signerInfos)
            throws KrbException {
        SignedContentInfo contentInfo = new SignedContentInfo();
        contentInfo.setContentType("1.2.840.113549.1.7.2");
        SignedData signedData = new SignedData();
        signedData.setVersion(version);
        if (digestAlgorithmIdentifiers != null) {
            signedData.setDigestAlgorithms(digestAlgorithmIdentifiers);
        }
        EncapsulatedContentInfo eContentInfo = new EncapsulatedContentInfo();
        eContentInfo.setContentType(oid);
        eContentInfo.setContent(data);
        signedData.setEncapContentInfo(eContentInfo);
        if (certificateSet != null) {
            signedData.setCertificates(certificateSet);
        }
        if (crls != null) {
            signedData.setCrls(crls);
        }
        if (signerInfos != null) {
            signedData.setSignerInfos(signerInfos);
        }
        contentInfo.setSignedData(signedData);
        return KrbCodec.encode(contentInfo);
    }

    public static byte[] eContentInfoCreate(byte[] data, String oid) throws KrbException {
        EncapsulatedContentInfo eContentInfo = new EncapsulatedContentInfo();
        eContentInfo.setContentType(oid);
        eContentInfo.setContent(data);
        return KrbCodec.encode(eContentInfo);
    }

    public static X509Certificate[] createCertChain(PkinitPlgCryptoContext cryptoContext)
            throws CertificateNotYetValidException, CertificateExpiredException {
        LOG.info("Building certificate chain.");

        // TODO Build client chain.
        X509Certificate[] clientChain = new X509Certificate[3];

        return clientChain;
    }

    public static boolean verifyKdcSan(String hostname, PrincipalName kdcPrincipal,
                                       List<Certificate> certificates) throws KrbException {

        if (hostname == null) {
            LOG.info("No pkinit_kdc_hostname values found in config file");
        } else {
            LOG.info("pkinit_kdc_hostname values found in config file");
        }

        try {
            List<PrincipalName> princs = cryptoRetrieveCertSans(certificates);
            if (princs != null) {
                for (PrincipalName princ : princs) {
                    LOG.info("PKINIT client found id-pkinit-san in KDC cert: " + princ.getName());
                }
                LOG.info("Checking pkinit sans.");

                if (princs.contains(kdcPrincipal)) {
                    LOG.info("pkinit san match found");
                    return true;
                } else {
                    LOG.info("no pkinit san match found");
                    return false;
                }
            } else {
                return false;
            }
        } catch (KrbException e) {
            String errMessage = "PKINIT client failed to decode SANs in KDC cert." + e;
            LOG.error(errMessage);
            throw new KrbException(KrbErrorCode.KDC_NAME_MISMATCH, errMessage);
        }
    }

    public static List<PrincipalName> cryptoRetrieveCertSans(List<Certificate> certificates)
            throws KrbException {
        if (certificates.size() == 0) {
            LOG.info("no certificate!");
            return null;
        }
        return cryptoRetrieveX509Sans(certificates);
    }

    public static List<PrincipalName> cryptoRetrieveX509Sans(List<Certificate> certificates)
            throws KrbException {

        List<PrincipalName> principalNames = new ArrayList<>();
        for (Certificate cert : certificates) {
            LOG.info("Looking for SANs in cert: " + cert.getTBSCertificate().getSubject());
            //TODO

        }
        return principalNames;
    }

    /**
     * Validates a chain of {@link X509Certificate}s.
     *
     * @param certificateList The certificate list
     * @param anchor The anchor
     * @throws CertificateException e
     * @throws NoSuchAlgorithmException e
     * @throws InvalidAlgorithmParameterException e
     * @throws CertPathValidatorException e
     * @throws IOException 
     */
    public static void validateChain(List<Certificate> certificateList, X509Certificate anchor)
            throws CertificateException, NoSuchAlgorithmException, NoSuchProviderException,
            InvalidAlgorithmParameterException, CertPathValidatorException, IOException {

        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        
        // Convert into a list of X509Certificates
        List<X509Certificate> certsList = new ArrayList<>(certificateList.size());
        for (Certificate cert : certificateList) {
            X509Certificate parsedCert = 
                (X509Certificate) certificateFactory.generateCertificate(
                    new ByteArrayInputStream(cert.encode()));
            certsList.add(parsedCert);
        }
        
        CertPath certPath = certificateFactory.generateCertPath(certsList);
        
        CertPathValidator cpv = CertPathValidator.getInstance("PKIX");

        TrustAnchor trustAnchor = new TrustAnchor(anchor, null);

        PKIXParameters parameters = new PKIXParameters(Collections.singleton(trustAnchor));
        parameters.setRevocationEnabled(false);

        cpv.validate(certPath, parameters);
    }

    /**
     * Create oid
     *
     * @param content The hex content
     * @return  The oid
     * @throws KrbException e
     */
    public static Asn1ObjectIdentifier createOid(String content) throws KrbException {
        Asn1ObjectIdentifier oid = new Asn1ObjectIdentifier();
        oid.useDER();
        KrbCodec.decode(HexUtil.hex2bytesFriendly(content), oid);
        return oid;
    }

    /**
     * Change the X509Certificate to Certificate
     *
     * @param x509Certificate The X509Certificate
     * @return The Certificate
     */
    public static Certificate changeToCertificate(X509Certificate x509Certificate) {

        Certificate certificate = new Certificate();
        try {
            certificate.decode(x509Certificate.getEncoded());
        } catch (IOException e) {
            LOG.error("Fail to decode certificate. " + e);
        } catch (CertificateEncodingException e) {
            LOG.error("Fail to encode x509 certificate. " + e);
        }
        return certificate;
    }
}
