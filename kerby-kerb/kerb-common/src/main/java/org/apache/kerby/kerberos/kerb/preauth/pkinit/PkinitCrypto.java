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

import org.apache.commons.ssl.Certificates;
import org.apache.kerby.kerberos.kerb.KrbErrorCode;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.spec.cms.DHParameter;
import org.apache.kerby.kerberos.kerb.spec.pa.pkinit.KdcDHKeyInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import sun.security.pkcs.ContentInfo;
import sun.security.pkcs.PKCS7;
import sun.security.pkcs.ParsingException;
import sun.security.pkcs.SignerInfo;
import sun.security.util.DerValue;
import sun.security.util.ObjectIdentifier;
import sun.security.x509.AlgorithmId;

import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPublicKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.List;

public class PkinitCrypto {

    private static final Logger LOG = LoggerFactory.getLogger(PkinitCrypto.class);

    public static KeyPair getKeyPair(DHParameterSpec dhParameterSpec) {
        String algo = "DH";
        KeyPairGenerator keyPairGenerator = null;
        try {
            keyPairGenerator = KeyPairGenerator.getInstance(algo);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        if (keyPairGenerator != null) {
            try {
                keyPairGenerator.initialize(dhParameterSpec);
            } catch (InvalidAlgorithmParameterException e) {
                e.printStackTrace();
            }
        }
        return keyPairGenerator.generateKeyPair();
    }

    public static PKCS7 verifyCMSSignedData(CMSMessageType cmsMsgType,
                                            byte[] signedData)
            throws IOException, KrbException {

        ObjectIdentifier oid = pkinitPKCS7Type2OID(cmsMsgType);
        if (oid == null) {
            throw new KrbException("Can't get the right oid ");
        }

        /* decode received CMS message */
        PKCS7 pkcs7 = null;
        try {
            pkcs7 = new PKCS7(signedData);
        } catch (ParsingException e) {
            e.printStackTrace();
        }
        if (pkcs7 == null) {
            LOG.error("failed to decode message");
            throw new KrbException("failed to decode message");
        }

        ObjectIdentifier etype = pkcs7.getContentInfo().getContentType();

        if (oid.equals(etype)) {
            LOG.info("CMS Verification successful");
        } else {
            LOG.error("Wrong oid in eContentType");
            throw new KrbException(KrbErrorCode.KDC_ERR_PREAUTH_FAILED, "Wrong oid in eContentType");
        }

        return pkcs7;
    }

    public static boolean isSigned(PKCS7 pkcs7) {
        /* Not actually signed; anonymous case */
        if (pkcs7.getSignerInfos().length == 0) {
            return false;
        } else {
            return true;
        }
    }

    public static ObjectIdentifier pkinitPKCS7Type2OID(CMSMessageType cmsMsgType) throws IOException {
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

    public static void serverCheckDH(PluginOpts pluginOpts, PkinitPlgCryptoContext cryptoctx,
                                     DHParameter dhParameter) throws KrbException {
         /* KDC SHOULD check to see if the key parameters satisfy its policy */
        int dhPrimeBits = dhParameter.getP().bitLength();
        if (dhPrimeBits < pluginOpts.dhMinBits) {
            String errMsg = "client sent dh params with " + dhPrimeBits
                    + "bits, we require " + pluginOpts.dhMinBits;
            LOG.error(errMsg);
            throw new KrbException(KrbErrorCode.KDC_ERR_DH_KEY_PARAMETERS_NOT_ACCEPTED, errMsg);
        }
        checkDHWellknown(cryptoctx, dhParameter, dhPrimeBits);
    }

    public static boolean checkDHWellknown(PkinitPlgCryptoContext cryptoctx,
                                           DHParameter dhParameter, int dhPrimeBits) throws KrbException {
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
     * @param dh2 The DHParameter
     */

    public static boolean pkinitCheckDhParams(DHParameterSpec dh1, DHParameter dh2) {

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

    public static DHPublicKey createDHPublicKey(BigInteger p, BigInteger g, BigInteger y) {
        DHPublicKeySpec dhPublicKeySpec = new DHPublicKeySpec(y, p, g);

        KeyFactory keyFactory = null;
        try {
            keyFactory = KeyFactory.getInstance("DH");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        DHPublicKey dhPublicKey = null;
        try {
            dhPublicKey = (DHPublicKey) keyFactory.generatePublic(dhPublicKeySpec);
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return dhPublicKey;
    }

    public static ByteArrayOutputStream cmsSignedDataCreate(byte[] data, ObjectIdentifier oid,
                                                            X509Certificate[] certificates) throws IOException {

        ContentInfo contentInfo = createContentInfo(data, oid);

        PKCS7 p7 = new PKCS7(new AlgorithmId[0], contentInfo, certificates, new SignerInfo[0]);
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        p7.encodeSignedData(bytes);
        return bytes;
    }

    public static ContentInfo createContentInfo(byte[] data, ObjectIdentifier oid) {

        ContentInfo contentInfo = new ContentInfo(
                oid,
                new DerValue(DerValue.tag_OctetString, data));
        return contentInfo;
    }

    public static boolean verifyKdcSan(String hostname, X509Certificate[] cert) {

        if(hostname == null) {
            LOG.info("No pkinit_kdc_hostname values found in config file");
        } else {
            LOG.info("pkinit_kdc_hostname values found in config file");
        }

        cryptoRetrieveCertSans(cert);
        return true;
    }

    public static void cryptoRetrieveCertSans(X509Certificate[] cert) {
        cryptoRetrieveX509Sans(cert);
    }

    public static void cryptoRetrieveX509Sans(X509Certificate[] cert) {

        if(cert == null) {
            LOG.info("no certificate!");
        }

        LOG.info("Looking for SANs in cert");
        String[] subjectAlts = Certificates.getDNSSubjectAlts(cert[0]);
    }
}
