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
package org.apache.kerby.kerberos.kerb.server.preauth.pkinit;

import org.apache.kerby.asn1.type.Asn1Integer;
import org.apache.kerby.asn1.type.Asn1ObjectIdentifier;
import org.apache.kerby.x509.type.Certificate;
import org.apache.kerby.cms.type.CertificateChoices;
import org.apache.kerby.cms.type.CertificateSet;
import org.apache.kerby.cms.type.ContentInfo;
import org.apache.kerby.cms.type.SignedData;
import org.apache.kerby.kerberos.kerb.KrbCodec;
import org.apache.kerby.kerberos.kerb.KrbErrorCode;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.common.CheckSumUtil;
import org.apache.kerby.kerberos.kerb.common.KrbUtil;
import org.apache.kerby.kerberos.kerb.crypto.dh.DhServer;
import org.apache.kerby.kerberos.kerb.preauth.PluginRequestContext;
import org.apache.kerby.kerberos.kerb.preauth.pkinit.CMSMessageType;
import org.apache.kerby.kerberos.kerb.preauth.pkinit.CertificateHelper;
import org.apache.kerby.kerberos.kerb.preauth.pkinit.PkinitCrypto;
import org.apache.kerby.kerberos.kerb.preauth.pkinit.PkinitPlgCryptoContext;
import org.apache.kerby.kerberos.kerb.preauth.pkinit.PkinitPreauthMeta;
import org.apache.kerby.kerberos.kerb.server.KdcContext;
import org.apache.kerby.kerberos.kerb.server.preauth.AbstractPreauthPlugin;
import org.apache.kerby.kerberos.kerb.server.request.KdcRequest;
import org.apache.kerby.kerberos.kerb.type.KerberosTime;
import org.apache.kerby.kerberos.kerb.type.base.CheckSum;
import org.apache.kerby.kerberos.kerb.type.base.CheckSumType;
import org.apache.kerby.kerberos.kerb.type.base.EncryptionKey;
import org.apache.kerby.kerberos.kerb.type.base.PrincipalName;
import org.apache.kerby.kerberos.kerb.type.kdc.KdcOption;
import org.apache.kerby.kerberos.kerb.type.pa.PaDataEntry;
import org.apache.kerby.kerberos.kerb.type.pa.PaDataType;
import org.apache.kerby.kerberos.kerb.type.pa.pkinit.AuthPack;
import org.apache.kerby.kerberos.kerb.type.pa.pkinit.DHRepInfo;
import org.apache.kerby.kerberos.kerb.type.pa.pkinit.KdcDHKeyInfo;
import org.apache.kerby.kerberos.kerb.type.pa.pkinit.PaPkAsRep;
import org.apache.kerby.kerberos.kerb.type.pa.pkinit.PaPkAsReq;
import org.apache.kerby.kerberos.kerb.type.pa.pkinit.PkAuthenticator;
import org.apache.kerby.x509.type.DHParameter;
import org.apache.kerby.x509.type.SubjectPublicKeyInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.interfaces.DHPublicKey;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Scanner;

public class PkinitPreauth extends AbstractPreauthPlugin {

    private static final Logger LOG = LoggerFactory.getLogger(PkinitPreauth.class);
    private final Map<String, PkinitKdcContext> pkinitContexts;

    public PkinitPreauth() {
        super(new PkinitPreauthMeta());

        pkinitContexts = new HashMap<String, PkinitKdcContext>(1);
    }

    @Override
    public void initWith(KdcContext kdcContext) {
        super.initWith(kdcContext);

        PkinitKdcContext tmp = new PkinitKdcContext();
        tmp.realm = kdcContext.getKdcRealm();

        String pkinitIdentity = kdcContext.getConfig().getPkinitIdentity();
        tmp.identityOpts.identity = pkinitIdentity;

        pkinitContexts.put(kdcContext.getKdcRealm(), tmp);
    }

    @Override
    public PluginRequestContext initRequestContext(KdcRequest kdcRequest) {
        PkinitRequestContext reqCtx = new PkinitRequestContext();

        //reqCtx.updateRequestOpts(pkinitContext.pluginOpts);

        return reqCtx;
    }

    @Override
    public boolean verify(KdcRequest kdcRequest, PluginRequestContext requestContext,
                          PaDataEntry paData) throws KrbException {

        LOG.info("pkinit verify padata: entered!");

        PkinitRequestContext reqCtx = (PkinitRequestContext) requestContext;
        PrincipalName serverPrincipal = kdcRequest.getServerEntry().getPrincipal();
        kdcRequest.setServerPrincipal(serverPrincipal);
        PkinitKdcContext pkinitContext = findContext(serverPrincipal);
        if (pkinitContext == null) {
            return false;
        }

        reqCtx.paType = paData.getPaDataType();
        if (paData.getPaDataType() == PaDataType.PK_AS_REQ) {

            LOG.info("processing PK_AS_REQ");
            PaPkAsReq paPkAsReq = KrbCodec.decode(paData.getPaDataValue(), PaPkAsReq.class);

            byte[] signedAuthPack = paPkAsReq.getSignedAuthPack();

            ContentInfo contentInfo = new ContentInfo();
            try {
                contentInfo.decode(signedAuthPack);
            } catch (IOException e) {
                e.printStackTrace();
            }

            SignedData signedData = contentInfo.getContentAs(SignedData.class);

            PkinitCrypto.verifyCMSSignedData(CMSMessageType.CMS_SIGN_CLIENT, signedData);

            Boolean isSigned = PkinitCrypto.isSigned(signedData);
            if (isSigned) {
                //TODO
                LOG.info("Signed data.");
            } else {
                PrincipalName clientPrincial = kdcRequest.getClientEntry().getPrincipal();
                PrincipalName anonymousPrincipal = KrbUtil.makeAnonymousPrincipal();

                /* If anonymous requests are being used, adjust the realm of the client principal. */
                if (kdcRequest.getKdcOptions().isFlagSet(KdcOption.REQUEST_ANONYMOUS)
                        && !KrbUtil.pricipalCompareIgnoreRealm(clientPrincial, anonymousPrincipal)) {
                    String errMsg = "Pkinit request not signed, but client not anonymous.";
                    LOG.error(errMsg);
                    throw new KrbException(KrbErrorCode.KDC_ERR_PREAUTH_FAILED, errMsg);
                }
            }

            AuthPack authPack = KrbCodec.decode(
                signedData.getEncapContentInfo().getContent(), AuthPack.class);

            PkAuthenticator pkAuthenticator = authPack.getPkAuthenticator();

            checkClockskew(kdcRequest, pkAuthenticator.getCtime());
            DHParameter dhParameter;

            if (kdcRequest.getReqBodyBytes() == null) {
                LOG.error("ReqBodyBytes isn't available");
                return false;
            }

            CheckSum expectedCheckSum = null;
            try {
                expectedCheckSum = CheckSumUtil.makeCheckSum(CheckSumType.NIST_SHA,
                        kdcRequest.getReqBodyBytes());
            } catch (KrbException e) {
                LOG.error("Unable to calculate AS REQ checksum.", e.getMessage());
            }
            byte[] receivedCheckSumByte = pkAuthenticator.getPaChecksum();

            if (expectedCheckSum.getChecksum().length != receivedCheckSumByte.length
                    || !Arrays.equals(expectedCheckSum.getChecksum(), receivedCheckSumByte)) {
                LOG.debug("received checksum length: " + receivedCheckSumByte.length
                        + ", expected checksum type: " + expectedCheckSum.getCksumtype()
                        + ", expected checksum length: " + expectedCheckSum.encodingLength());
                String errorMessage = "Failed to match the checksum.";
                LOG.error(errorMessage);
                throw new KrbException(KrbErrorCode.KDC_ERR_PA_CHECKSUM_MUST_BE_INCLUDED, errorMessage);
            }

            SubjectPublicKeyInfo publicKeyInfo = authPack.getClientPublicValue();

            if (publicKeyInfo.getSubjectPubKey() != null) {
                dhParameter = authPack.getClientPublicValue().getAlgorithm().getParametersAs(DHParameter.class);
                PkinitCrypto.serverCheckDH(pkinitContext.pluginOpts, pkinitContext.cryptoctx, dhParameter);

                byte[] clientSubjectPubKey = publicKeyInfo.getSubjectPubKey().getValue();
                Asn1Integer clientPubKey = KrbCodec.decode(clientSubjectPubKey, Asn1Integer.class);
                BigInteger y = clientPubKey.getValue();

                BigInteger p = dhParameter.getP();
                BigInteger g = dhParameter.getG();

                DHPublicKey dhPublicKey = PkinitCrypto.createDHPublicKey(p, g, y);

                DhServer server = new DhServer();
                DHPublicKey serverPubKey = null;
                try {
                    serverPubKey = (DHPublicKey) server.initAndDoPhase(dhPublicKey.getEncoded());
                } catch (Exception e) {
                    LOG.error("Fail to create server public key.", e);
                }
                EncryptionKey secretKey = server.generateKey(null, null, kdcRequest.getEncryptionType());

                // Set the DH shared key as the client key
                kdcRequest.setClientKey(secretKey);

                String identity = pkinitContext.identityOpts.identity;

                PaPkAsRep paPkAsRep = makePaPkAsRep(pkinitContext.cryptoctx, serverPubKey, identity);
                PaDataEntry paDataEntry = makeEntry(paPkAsRep);

                kdcRequest.getPreauthContext().getOutputPaData().add(paDataEntry);
            } else {
                if (!isSigned) {
                /*Anonymous pkinit requires DH*/
                    String errMessage = "Anonymous pkinit without DH public value not supported.";
                    LOG.error(errMessage);
                    throw new KrbException(KrbErrorCode.KDC_ERR_PREAUTH_FAILED, errMessage);
                } else {
                    // rsa
                }
            }
        }

        return true;
    }

    private PkinitKdcContext findContext(PrincipalName principal) {
        String realm = principal.getRealm();
        if (pkinitContexts.containsKey(realm)) {
            return pkinitContexts.get(realm);
        }
        return null;
    }

    /**
     * Make padata entry.
     *
     * @param paPkAsRep The PaPkAsRep
     * @return PaDataEntry to be made.
     */
    private PaDataEntry makeEntry(PaPkAsRep paPkAsRep) throws KrbException {

        PaDataEntry paDataEntry = new PaDataEntry();
        paDataEntry.setPaDataType(PaDataType.PK_AS_REP);
        //TODO CHOICE
        paDataEntry.setPaDataValue(paPkAsRep.encode());
        return paDataEntry;
    }

    private PaPkAsRep makePaPkAsRep(PkinitPlgCryptoContext cryptoContext,
                                    DHPublicKey severPubKey, String identityString) {

        List<String> identityList = Arrays.asList(identityString.split(","));

        List<X509Certificate> certificates = new ArrayList<>();
        for (String identity : identityList) {
            File file = new File(identity);
            try {
                Scanner scanner = new Scanner(file);
                String found = scanner.findInLine("CERTIFICATE");

                if (found != null) {
                    InputStream res = null;
                    try {
                        res = new FileInputStream(identity);
                    } catch (FileNotFoundException e) {
                        e.printStackTrace();
                    }
                    X509Certificate certificate = null;
                    try {
                        certificate = (X509Certificate) CertificateHelper.loadCerts(res).iterator().next();
                    } catch (KrbException e) {
                        e.printStackTrace();
                    }
                    certificates.add(certificate);
                }
            } catch (FileNotFoundException e) {
                e.getMessage();
            }
        }

        PaPkAsRep paPkAsRep = new PaPkAsRep();
        DHRepInfo dhRepInfo = new DHRepInfo();
        KdcDHKeyInfo kdcDhKeyInfo = new KdcDHKeyInfo();

        Asn1Integer publickey = new Asn1Integer(severPubKey.getY());
        kdcDhKeyInfo.setSubjectPublicKey(publickey.encode());
        kdcDhKeyInfo.setNonce(0);
        kdcDhKeyInfo.setDHKeyExpiration(
                new KerberosTime(System.currentTimeMillis() + KerberosTime.DAY));

        byte[] signedDataBytes = null;

        CertificateSet certificateSet = new CertificateSet();
        for(X509Certificate x509Certificate : certificates) {
            Certificate certificate = PkinitCrypto.changeCertificate(x509Certificate);
            CertificateChoices certificateChoices = new CertificateChoices();
            certificateChoices.setCertificate(certificate);
            certificateSet.addElement(certificateChoices);
        }

        Asn1ObjectIdentifier oid = cryptoContext.getIdPkinitDHKeyDataOID();
        signedDataBytes = PkinitCrypto.cmsSignedDataCreate(kdcDhKeyInfo.encode(), oid, 3, null,
                certificateSet, null, null);

        dhRepInfo.setDHSignedData(signedDataBytes);

        paPkAsRep.setDHRepInfo(dhRepInfo);

        return paPkAsRep;
    }

    public boolean checkClockskew(KdcRequest kdcRequest, KerberosTime time) throws KrbException {
        long clockSkew = kdcRequest.getKdcContext().getConfig().getAllowableClockSkew() * 1000;

        if (!time.isInClockSkew(clockSkew)) {
            throw new KrbException(KrbErrorCode.KDC_ERR_PREAUTH_FAILED);
        } else {
            return true;
        }
    }
}
