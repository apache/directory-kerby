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
package org.apache.kerby.kerberos.kerb.preauth.pkinit;

import org.apache.kerby.kerberos.kerb.KrbCodec;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.type.pa.pkinit.AuthPack;
import org.apache.kerby.kerberos.kerb.type.pa.pkinit.KdcDhKeyInfo;
import org.apache.kerby.kerberos.kerb.type.pa.pkinit.ReplyKeyPack;
import org.apache.kerby.pkix.PkiException;
import org.apache.kerby.pkix.PkiUtil;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;


/**
 * Encapsulates working with PKINIT signed data structures.
 */
public class PkinitUtil {
    private static final String ID_PKINIT_AUTHDATA = "1.3.6.1.5.2.3.1";
    //private static final String ID_PKINIT_DHKEYDATA = "1.3.6.1.5.2.3.2";
    //private static final String ID_PKINIT_RKEYDATA = "1.3.6.1.5.2.3.3";

    /**
     * Uses a private key to sign data in a CMS SignedData structure and returns
     * the encoded CMS SignedData as bytes.
     *
     * 'signedAuthPack' contains a CMS type ContentInfo encoded according to [RFC3852].
     * The contentType field of the type ContentInfo is id-signedData (1.2.840.113549.1.7.2),
     * and the content field is a SignedData.
     *
     * The eContentType field for the type SignedData is id-pkinit-authData (1.3.6.1.5.2.3.1),
     * and the eContent field contains the DER encoding of the type AuthPack.
     * @param privateKey The private key
     * @param certificate The certificate
     * @param  authPack The auth pack
     * @throws KrbException e
     */
    public static byte[] getSignedAuthPack(PrivateKey privateKey, X509Certificate certificate,
                                           AuthPack authPack) throws KrbException {
        byte[] dataToSign = KrbCodec.encode(authPack);
        byte[] signedData;
        try {
            signedData = PkiUtil.getSignedData(privateKey, certificate, dataToSign, ID_PKINIT_AUTHDATA);
        } catch (PkiException e) {
            throw new KrbException("Failed to sign data", e);
        }

        return signedData;
    }


    /**
     * Uses a private key to sign data in a CMS SignedData structure and returns
     * the encoded CMS SignedData as bytes.
     *
     * 'dhSignedData' contains a CMS type ContentInfo encoded according to [RFC3852].
     * The contentType field of the type ContentInfo is id-signedData (1.2.840.113549.1.7.2),
     * and the content field is a SignedData.
     *
     * The eContentType field for the type SignedData is id-pkinit-DHKeyData (1.3.6.1.5.2.3.2),
     * and the eContent field contains the DER encoding of the type KDCDHKeyInfo.
     *
     * @param privateKey The private Key
     * @param certificate The certificate
     * @param kdcDhKeyInfo The kdc dh key info
     * @throws KrbException e
     */
    public static byte[] getSignedKdcDhKeyInfo(PrivateKey privateKey, X509Certificate certificate,
                                               KdcDhKeyInfo kdcDhKeyInfo) throws KrbException {
        byte[] dataToSign = KrbCodec.encode(kdcDhKeyInfo);
        byte[] signedData;
        try {
            signedData = PkiUtil.getSignedData(privateKey, certificate, dataToSign, ID_PKINIT_AUTHDATA);
        } catch (PkiException e) {
            throw new KrbException("Failed to sign data", e);
        }

        return signedData;
    }


    /**
     * Uses a private key to sign data in a CMS SignedData structure and returns
     * the encoded CMS SignedData as bytes.
     *
     * Selected when public key encryption is used.
     *
     * The eContentType field for the inner type SignedData (when unencrypted) is
     * id-pkinit-rkeyData (1.3.6.1.5.2.3.3) and the eContent field contains the
     * DER encoding of the type ReplyKeyPack.
     * @param privateKey The private key
     * @param  certificate The certificate
     * @param replyKeyPack The reply key pack
     * @throws KrbException e
     */
    public static byte[] getSignedReplyKeyPack(PrivateKey privateKey, X509Certificate certificate,
                                               ReplyKeyPack replyKeyPack) throws KrbException {
        byte[] dataToSign = KrbCodec.encode(replyKeyPack);
        byte[] signedData;
        try {
            signedData = PkiUtil.getSignedData(privateKey, certificate, dataToSign, ID_PKINIT_AUTHDATA);
        } catch (PkiException e) {
            throw new KrbException("Failed to sign data", e);
        }

        return signedData;
    }
}
