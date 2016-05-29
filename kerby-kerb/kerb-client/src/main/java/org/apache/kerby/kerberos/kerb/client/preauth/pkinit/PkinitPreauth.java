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

import org.apache.kerby.KOptions;
import org.apache.kerby.asn1.type.Asn1Integer;
import org.apache.kerby.asn1.type.Asn1ObjectIdentifier;
import org.apache.kerby.cms.type.CertificateChoices;
import org.apache.kerby.cms.type.CertificateSet;
import org.apache.kerby.cms.type.ContentInfo;
import org.apache.kerby.cms.type.SignedData;
import org.apache.kerby.kerberos.kerb.KrbCodec;
import org.apache.kerby.kerberos.kerb.KrbErrorCode;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.client.KrbContext;
import org.apache.kerby.kerberos.kerb.client.PkinitOption;
import org.apache.kerby.kerberos.kerb.client.preauth.AbstractPreauthPlugin;
import org.apache.kerby.kerberos.kerb.client.request.KdcRequest;
import org.apache.kerby.kerberos.kerb.common.CheckSumUtil;
import org.apache.kerby.kerberos.kerb.common.KrbUtil;
import org.apache.kerby.kerberos.kerb.crypto.dh.DhGroup;
import org.apache.kerby.kerberos.kerb.crypto.dh.DiffieHellmanClient;
import org.apache.kerby.kerberos.kerb.preauth.PaFlag;
import org.apache.kerby.kerberos.kerb.preauth.PaFlags;
import org.apache.kerby.kerberos.kerb.preauth.PluginRequestContext;
import org.apache.kerby.kerberos.kerb.preauth.pkinit.CertificateHelper;
import org.apache.kerby.kerberos.kerb.preauth.pkinit.CmsMessageType;
import org.apache.kerby.kerberos.kerb.preauth.pkinit.PkinitCrypto;
import org.apache.kerby.kerberos.kerb.preauth.pkinit.PkinitIdenity;
import org.apache.kerby.kerberos.kerb.preauth.pkinit.PkinitPlgCryptoContext;
import org.apache.kerby.kerberos.kerb.preauth.pkinit.PkinitPreauthMeta;
import org.apache.kerby.kerberos.kerb.type.KerberosTime;
import org.apache.kerby.kerberos.kerb.type.base.CheckSum;
import org.apache.kerby.kerberos.kerb.type.base.CheckSumType;
import org.apache.kerby.kerberos.kerb.type.base.EncryptionKey;
import org.apache.kerby.kerberos.kerb.type.base.EncryptionType;
import org.apache.kerby.kerberos.kerb.type.base.PrincipalName;
import org.apache.kerby.kerberos.kerb.type.pa.PaData;
import org.apache.kerby.kerberos.kerb.type.pa.PaDataEntry;
import org.apache.kerby.kerberos.kerb.type.pa.PaDataType;
import org.apache.kerby.kerberos.kerb.type.pa.pkinit.AuthPack;
import org.apache.kerby.kerberos.kerb.type.pa.pkinit.DhRepInfo;
import org.apache.kerby.kerberos.kerb.type.pa.pkinit.KdcDhKeyInfo;
import org.apache.kerby.kerberos.kerb.type.pa.pkinit.PaPkAsRep;
import org.apache.kerby.kerberos.kerb.type.pa.pkinit.PaPkAsReq;
import org.apache.kerby.kerberos.kerb.type.pa.pkinit.PkAuthenticator;
import org.apache.kerby.kerberos.kerb.type.pa.pkinit.TrustedCertifiers;
import org.apache.kerby.x509.type.AlgorithmIdentifier;
import org.apache.kerby.x509.type.Certificate;
import org.apache.kerby.x509.type.DhParameter;
import org.apache.kerby.x509.type.SubjectPublicKeyInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.List;

public class PkinitPreauth extends AbstractPreauthPlugin {
    private static final Logger LOG = LoggerFactory.getLogger(PkinitPreauth.class);

    private PkinitContext pkinitContext;

    public PkinitPreauth() {
        super(new PkinitPreauthMeta());
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void init(KrbContext context) {
        super.init(context);
        this.pkinitContext = new PkinitContext();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public PluginRequestContext initRequestContext(KdcRequest kdcRequest) {
        PkinitRequestContext reqCtx = new PkinitRequestContext();

        reqCtx.updateRequestOpts(pkinitContext.pluginOpts);

        return reqCtx;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void setPreauthOptions(KdcRequest kdcRequest,
                                  PluginRequestContext requestContext,
                                  KOptions options) {
        if (options.contains(PkinitOption.X509_IDENTITY)) {
            pkinitContext.identityOpts.identity =
                    options.getStringOption(PkinitOption.X509_IDENTITY);
        }

        if (options.contains(PkinitOption.X509_ANCHORS)) {
            String anchorsString = options.getStringOption(PkinitOption.X509_ANCHORS);

            List<String> anchors;
            if (anchorsString == null) {
                anchors = kdcRequest.getContext().getConfig().getPkinitAnchors();
            } else {
                anchors = Arrays.asList(anchorsString);
            }
            pkinitContext.identityOpts.anchors.addAll(anchors);
        }

        if (options.contains(PkinitOption.USING_RSA)) {
            pkinitContext.pluginOpts.usingRsa =
                    options.getBooleanOption(PkinitOption.USING_RSA, true);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void prepareQuestions(KdcRequest kdcRequest,
                                 PluginRequestContext requestContext) {

        PkinitRequestContext reqCtx = (PkinitRequestContext) requestContext;

        if (!reqCtx.identityInitialized) {
            PkinitIdenity.initialize(reqCtx.identityOpts, kdcRequest.getClientPrincipal());
            reqCtx.identityInitialized = true;
        }

        // Might have questions asking for password to access the private key
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void tryFirst(KdcRequest kdcRequest,
                         PluginRequestContext requestContext,
                         PaData outPadata) throws KrbException {

        /* XXX PKINIT RFC says that nonce in PKAuthenticator doesn't have be the
         * same as in the AS_REQ. However, if we pick a different nonce, then we
         * need to remember that info when AS_REP is returned. Here choose to
         * reuse the AS_REQ nonce.
         */
        int nonce = kdcRequest.getChosenNonce();

        // Get the current time
        long now = System.currentTimeMillis();
        Calendar calendar = Calendar.getInstance();
        calendar.setTime(new Date(now));
        int cusec = calendar.get(Calendar.SECOND);
        KerberosTime ctime = new KerberosTime(now);

        /* checksum of the encoded KDC-REQ-BODY */
        CheckSum checkSum = null;
        try {
            checkSum = CheckSumUtil.makeCheckSum(CheckSumType.NIST_SHA,
                KrbCodec.encode(kdcRequest.getKdcReq().getReqBody()));
        } catch (KrbException e) {
            throw new KrbException("Fail to encode checksum.", e);
        }

        PaPkAsReq paPkAsReq = makePaPkAsReq(kdcRequest, (PkinitRequestContext) requestContext,
                cusec, ctime, nonce, checkSum);
        outPadata.addElement(makeEntry(paPkAsReq));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean process(KdcRequest kdcRequest,
                           PluginRequestContext requestContext,
                           PaDataEntry inPadata,
                           PaData outPadata) throws KrbException {

        PkinitRequestContext reqCtx = (PkinitRequestContext) requestContext;
        if (inPadata == null) {
            return false;
        }

        boolean processingRequest = false;
        switch (inPadata.getPaDataType()) {
            case PK_AS_REQ:
                processingRequest = true;
                break;
            case PK_AS_REP:
            default:
                break;
        }

        if (processingRequest) {
            generateRequest(reqCtx, kdcRequest, outPadata);
            return true;
        } else {
            EncryptionType encType = kdcRequest.getEncType();
            processReply(kdcRequest, reqCtx, inPadata, encType);
            return true;
        }
    }

    @SuppressWarnings("unused")
    private void generateRequest(PkinitRequestContext reqCtx, KdcRequest kdcRequest,
                                 PaData outPadata) {

    }

    @SuppressWarnings("unused")
    private PaPkAsReq makePaPkAsReq(KdcRequest kdcRequest,
                                    PkinitRequestContext reqCtx,
                                    int cusec, KerberosTime ctime, int nonce, CheckSum checkSum) throws KrbException {
        KdcRequest kdc = kdcRequest;

        LOG.info("Making the PK_AS_REQ.");
        PaPkAsReq paPkAsReq = new PaPkAsReq();
        AuthPack authPack = new AuthPack();
        PkAuthenticator pkAuthen = new PkAuthenticator();

        boolean usingRsa = pkinitContext.pluginOpts.usingRsa;
        reqCtx.paType = PaDataType.PK_AS_REQ;

        pkAuthen.setCusec(cusec);
        pkAuthen.setCtime(ctime);
        pkAuthen.setNonce(nonce);
        pkAuthen.setPaChecksum(checkSum.getChecksum());
        authPack.setPkAuthenticator(pkAuthen);
        authPack.setsupportedCmsTypes(pkinitContext.pluginOpts.createSupportedCMSTypes());

        if (!usingRsa) {
            // DH case
            LOG.info("DH key transport algorithm.");

            String content = "0x06 07 2A 86 48 ce 3e 02 01";
            Asn1ObjectIdentifier dhOid = PkinitCrypto.createOid(content);
            AlgorithmIdentifier dhAlg = new AlgorithmIdentifier();
            dhAlg.setAlgorithm(dhOid.getValue());

            DiffieHellmanClient client = new DiffieHellmanClient();

            DHPublicKey clientPubKey = null;
            try {
                clientPubKey = client.init(DhGroup.MODP_GROUP2);
            } catch (Exception e) {
                e.printStackTrace();
            }

            reqCtx.setDhClient(client);

            DHParameterSpec type = null;
            try {
                type = clientPubKey.getParams();
            } catch (Exception e) {
                e.printStackTrace();
            }
            BigInteger q = type.getP().shiftRight(1);
            DhParameter dhParameter = new DhParameter();
            dhParameter.setP(type.getP());
            dhParameter.setG(type.getG());
            dhParameter.setQ(q);
            dhAlg.setParameters(dhParameter);

            SubjectPublicKeyInfo pubInfo = new SubjectPublicKeyInfo();
            pubInfo.setAlgorithm(dhAlg);

            Asn1Integer publickey = new Asn1Integer(clientPubKey.getY());
            pubInfo.setSubjectPubKey(KrbCodec.encode(publickey));

            authPack.setClientPublicValue(pubInfo);

            // DhNonce dhNonce = new DhNonce();
            // authPack.setClientDhNonce(dhNonce);
            byte[] signedAuthPack = signAuthPack(authPack);
            paPkAsReq.setSignedAuthPack(signedAuthPack);

        } else {
            LOG.info("RSA key transport algorithm");
            // authPack.setClientPublicValue(null);
        }

        TrustedCertifiers trustedCertifiers = pkinitContext.pluginOpts.createTrustedCertifiers();
        paPkAsReq.setTrustedCertifiers(trustedCertifiers);

        // byte[] kdcPkId = pkinitContext.pluginOpts.createIssuerAndSerial();
        // paPkAsReq.setKdcPkId(kdcPkId);

        return paPkAsReq;
    }

    private byte[] signAuthPack(AuthPack authPack) throws KrbException {

        String oid = PkinitPlgCryptoContext.getIdPkinitAuthDataOID();

        byte[] signedDataBytes = PkinitCrypto.eContentInfoCreate(
                KrbCodec.encode(authPack), oid);

        return signedDataBytes;
    }

    private void processReply(KdcRequest kdcRequest,
                              PkinitRequestContext reqCtx,
                              PaDataEntry paEntry,
                              EncryptionType encType) throws KrbException {

        // Parse PA-PK-AS-REP message.
        if (paEntry.getPaDataType() == PaDataType.PK_AS_REP) {
            LOG.info("processing PK_AS_REP");

            PaPkAsRep paPkAsRep = KrbCodec.decode(paEntry.getPaDataValue(), PaPkAsRep.class);
            DhRepInfo dhRepInfo = paPkAsRep.getDHRepInfo();

            byte[] dhSignedData = dhRepInfo.getDHSignedData();

            ContentInfo contentInfo = new ContentInfo();
            try {
                contentInfo.decode(dhSignedData);
            } catch (IOException e) {
                e.printStackTrace();
            }

            SignedData signedData = contentInfo.getContentAs(SignedData.class);

            PkinitCrypto.verifyCmsSignedData(
                    CmsMessageType.CMS_SIGN_SERVER, signedData);

            String anchorFileName = kdcRequest.getContext().getConfig().getPkinitAnchors().get(0);

            X509Certificate x509Certificate = null;
            try {
                x509Certificate = (X509Certificate) CertificateHelper.loadCerts(
                        anchorFileName).iterator().next();
            } catch (KrbException e) {
                e.printStackTrace();
            }
            Certificate archorCertificate = PkinitCrypto.changeToCertificate(x509Certificate);

            CertificateSet certificateSet = signedData.getCertificates();
            List<Certificate> certificates = new ArrayList<>();
            if (certificateSet != null) {
                List<CertificateChoices> certificateChoicesList = certificateSet.getElements();
                for (CertificateChoices certificateChoices : certificateChoicesList) {
                    certificates.add(certificateChoices.getCertificate());
                }
            }
            try {
                PkinitCrypto.validateChain(certificates, archorCertificate);
            } catch (Exception e) {
                throw new KrbException(KrbErrorCode.KDC_ERR_INVALID_CERTIFICATE, e);
            }

            PrincipalName kdcPrincipal = KrbUtil.makeTgsPrincipal(
                    kdcRequest.getContext().getConfig().getKdcRealm());
            //TODO USE CertificateSet
            boolean validSan = PkinitCrypto.verifyKdcSan(
                    kdcRequest.getContext().getConfig().getPkinitKdcHostName(), kdcPrincipal,
                    certificates);
            if (!validSan) {
                LOG.error("Did not find an acceptable SAN in KDC certificate");
            }

            LOG.info("skipping EKU check");

            LOG.info("as_rep: DH key transport algorithm");
            KdcDhKeyInfo kdcDhKeyInfo = new KdcDhKeyInfo();
            try {
                kdcDhKeyInfo.decode(signedData.getEncapContentInfo().getContent());
            } catch (IOException e) {
                String errMessage = "failed to decode KdcDhKeyInfo " + e.getMessage();
                LOG.error(errMessage);
                throw new KrbException(errMessage);
            }

            byte[] subjectPublicKey = kdcDhKeyInfo.getSubjectPublicKey().getValue();

            Asn1Integer clientPubKey = KrbCodec.decode(subjectPublicKey, Asn1Integer.class);
            BigInteger y = clientPubKey.getValue();

            DiffieHellmanClient client = reqCtx.getDhClient();
            BigInteger p = client.getDhParam().getP();
            BigInteger g = client.getDhParam().getG();

            DHPublicKey dhPublicKey = PkinitCrypto.createDHPublicKey(p, g, y);

            EncryptionKey secretKey = null;
            try {
                client.doPhase(dhPublicKey.getEncoded());
                secretKey = client.generateKey(null, null, encType);
            } catch (Exception e) {
                e.printStackTrace();
            }
            // Set the DH shared key as the client key
            if (secretKey == null) {
                throw new KrbException("Fail to create client key.");
            } else {
                kdcRequest.setAsKey(secretKey);
            }
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean tryAgain(KdcRequest kdcRequest,
                            PluginRequestContext requestContext,
                            PaDataType preauthType,
                            PaData errPadata,
                            PaData outPadata) {

        PkinitRequestContext reqCtx = (PkinitRequestContext) requestContext;
        if (reqCtx.paType != preauthType && errPadata == null) {
            return false;
        }

        boolean doAgain = false;
        for (PaDataEntry pde : errPadata.getElements()) {
            //   switch (pde.getPaDataType()) {
            // TODO
            //    }
            System.out.println(pde.getPaDataType());
        }

        if (doAgain) {
            generateRequest(reqCtx, kdcRequest, outPadata);
        }

        return false;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public PaFlags getFlags(PaDataType paType) {
        PaFlags paFlags = new PaFlags(0);
        paFlags.setFlag(PaFlag.PA_REAL);

        return paFlags;
    }

    /**
     * Make padata entry.
     *
     * @param paPkAsReq The PaPkAsReq
     * @return PaDataEntry to be made.
     */
    private PaDataEntry makeEntry(PaPkAsReq paPkAsReq) throws KrbException {
        PaDataEntry paDataEntry = new PaDataEntry();
        paDataEntry.setPaDataType(PaDataType.PK_AS_REQ);
        paDataEntry.setPaDataValue(KrbCodec.encode(paPkAsReq));
        return paDataEntry;
    }
}
