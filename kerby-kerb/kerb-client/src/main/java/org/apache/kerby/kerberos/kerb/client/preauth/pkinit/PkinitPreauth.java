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
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.client.KrbContext;
import org.apache.kerby.kerberos.kerb.client.KrbOption;
import org.apache.kerby.kerberos.kerb.client.preauth.AbstractPreauthPlugin;
import org.apache.kerby.kerberos.kerb.client.request.KdcRequest;
import org.apache.kerby.kerberos.kerb.common.CheckSumUtil;
import org.apache.kerby.kerberos.kerb.crypto.dh.DhClient;
import org.apache.kerby.kerberos.kerb.crypto.dh.DhGroup;
import org.apache.kerby.kerberos.kerb.preauth.PaFlag;
import org.apache.kerby.kerberos.kerb.preauth.PaFlags;
import org.apache.kerby.kerberos.kerb.preauth.PluginRequestContext;
import org.apache.kerby.kerberos.kerb.preauth.pkinit.CertificateHelper;
import org.apache.kerby.kerberos.kerb.preauth.pkinit.PkinitCrypto;
import org.apache.kerby.kerberos.kerb.preauth.pkinit.PkinitIdenity;
import org.apache.kerby.kerberos.kerb.preauth.pkinit.PkinitPreauthMeta;
import org.apache.kerby.kerberos.kerb.type.KerberosTime;
import org.apache.kerby.kerberos.kerb.type.base.CheckSum;
import org.apache.kerby.kerberos.kerb.type.base.CheckSumType;
import org.apache.kerby.kerberos.kerb.type.base.EncryptionKey;
import org.apache.kerby.kerberos.kerb.type.base.EncryptionType;
import org.apache.kerby.kerberos.kerb.type.pa.PaData;
import org.apache.kerby.kerberos.kerb.type.pa.PaDataEntry;
import org.apache.kerby.kerberos.kerb.type.pa.PaDataType;
import org.apache.kerby.kerberos.kerb.type.pa.pkinit.AuthPack;
import org.apache.kerby.kerberos.kerb.type.pa.pkinit.PaPkAsReq;
import org.apache.kerby.kerberos.kerb.type.pa.pkinit.PkAuthenticator;
import org.apache.kerby.kerberos.kerb.type.pa.pkinit.TrustedCertifiers;
import org.apache.kerby.x509.type.AlgorithmIdentifier;
import org.apache.kerby.x509.type.DHParameter;
import org.apache.kerby.x509.type.SubjectPublicKeyInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.X509Certificate;
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
        if (options.contains(KrbOption.PKINIT_X509_IDENTITY)) {
            pkinitContext.identityOpts.identity =
                    options.getStringOption(KrbOption.PKINIT_X509_IDENTITY);
        }

        if (options.contains(KrbOption.PKINIT_X509_ANCHORS)) {
            String anchorsString = options.getStringOption(KrbOption.PKINIT_X509_ANCHORS);

            List<String> anchors;
            if (anchorsString == null) {
                anchors = kdcRequest.getContext().getConfig().getPkinitAnchors();
            } else {
                anchors = Arrays.asList(anchorsString);
            }
            pkinitContext.identityOpts.anchors.addAll(anchors);
        }

        if (options.contains(KrbOption.PKINIT_USING_RSA)) {
            pkinitContext.pluginOpts.usingRsa =
                    options.getBooleanOption(KrbOption.PKINIT_USING_RSA, true);
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
                    kdcRequest.getKdcReq().getReqBody().encode());
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
                break;
        }

        if (processingRequest) {
            generateRequest(reqCtx, kdcRequest, outPadata);
        } else {
            EncryptionType encType = kdcRequest.getEncType();
            processReply(kdcRequest, reqCtx, inPadata, encType);
        }

        return false;
    }

    private void generateRequest(PkinitRequestContext reqCtx, KdcRequest kdcRequest,
                                 PaData outPadata) {

    }

    private PaPkAsReq makePaPkAsReq(KdcRequest kdcRequest,
                                    PkinitRequestContext reqCtx,
                                    int cusec, KerberosTime ctime, int nonce, CheckSum checkSum) {

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

//        pkAuthen.setPaChecksum(checkSum.encode());

        authPack.setPkAuthenticator(pkAuthen);
        authPack.setsupportedCmsTypes(pkinitContext.pluginOpts.createSupportedCMSTypes());

        String certFile = null;
        if (!usingRsa) {
            // DH case
            LOG.info("DH key transport algorithm.");

            AlgorithmIdentifier dhAlg = new AlgorithmIdentifier();

//            byte[] dh_oid = new byte[]{0, 7, (byte) 0x2A, (byte) 0x86, (byte) 0x48, (byte) 0xce,
//                    (byte) 0x3e, (byte) 0x02, (byte) 0x01};
//            String dhOidStr = Utf8.toString(dh_oid);
//            String dhOidStr = "0.7.42.840.10046.2.1";

            String content = "0x06 07 2A 86 48 ce 3e 02 01";
            Asn1ObjectIdentifier dhOid = PkinitCrypto.createOid(content);
            dhAlg.setAlgorithm(dhOid);

            DhClient client = new DhClient();

            DHPublicKey clientPubKey = null;
            try {
                clientPubKey = client.init(DhGroup.MODP_GROUP14);
            } catch (Exception e) {
                e.printStackTrace();
            }

            kdcRequest.setDhClient(client);

            DHParameterSpec type = clientPubKey.getParams();
            BigInteger q = type.getP().shiftRight(1);
            DHParameter dhParameter = new DHParameter();
            dhParameter.setP(type.getP());
            dhParameter.setG(type.getG());
            dhParameter.setQ(q);
            dhAlg.setParameters(dhParameter);

            SubjectPublicKeyInfo pubInfo = new SubjectPublicKeyInfo();
            pubInfo.setAlgorithm(dhAlg);

            Asn1Integer publickey = new Asn1Integer(clientPubKey.getY());
            pubInfo.setSubjectPubKey(publickey.encode());

            authPack.setClientPublicValue(pubInfo);

//            DHNonce dhNonce = new DHNonce();
//            authPack.setClientDhNonce(dhNonce);

            List<String> archors = pkinitContext.identityOpts.anchors;
            certFile = archors.get(0);

        } else {
            LOG.info("RSA key transport algorithm");
//            authPack.setClientPublicValue(null);
            certFile = pkinitContext.identityOpts.identity;
        }

        X509Certificate certificate = null;
        try {
            certificate = (X509Certificate) CertificateHelper.loadCerts(
                    certFile).iterator().next();
        } catch (KrbException e) {
            e.printStackTrace();
        }

        X509Certificate[] certificates = {certificate};

        byte[] signedAuthPack = signAuthPack(kdcRequest, authPack, certificates);

        paPkAsReq.setSignedAuthPack(signedAuthPack);

        TrustedCertifiers trustedCertifiers = pkinitContext.pluginOpts.createTrustedCertifiers();
        paPkAsReq.setTrustedCertifiers(trustedCertifiers);

//        byte[] kdcPkId = pkinitContext.pluginOpts.createIssuerAndSerial();
//        paPkAsReq.setKdcPkId(kdcPkId);

        return paPkAsReq;
    }

    private byte[] signAuthPack(KdcRequest kdcRequest, AuthPack authPack, X509Certificate[] certificates) {

        byte[] signedDataBytes = new byte[0];
        try {
            signedDataBytes = PkinitCrypto.cmsSignedDataCreate(pkinitContext.cryptoctx, authPack.encode(),
                    pkinitContext.cryptoctx.getIdPkinitAuthDataOID(), certificates).toByteArray();
        } catch (IOException e) {
            e.printStackTrace();
        }
//        signedDataBytes = PkinitCrypto.cmsSignedDataCreate(authPack.encode());

        return signedDataBytes;
    }

    private void processReply(KdcRequest kdcRequest,
                              PkinitRequestContext reqCtx,
                              PaDataEntry inPadata,
                              EncryptionType encType) {

        EncryptionKey asKey = null;

        // TODO

        kdcRequest.setAsKey(asKey);
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
            System.out.println();
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
        paDataEntry.setPaDataValue(paPkAsReq.encode());
        return paDataEntry;
    }
}
