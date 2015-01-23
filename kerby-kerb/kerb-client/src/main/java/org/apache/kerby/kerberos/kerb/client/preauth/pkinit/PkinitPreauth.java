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

import org.apache.kerby.kerberos.kerb.client.KrbContext;
import org.apache.kerby.kerberos.kerb.client.KrbOption;
import org.apache.kerby.kerberos.kerb.client.KrbOptions;
import org.apache.kerby.kerberos.kerb.client.preauth.AbstractPreauthPlugin;
import org.apache.kerby.kerberos.kerb.preauth.PluginRequestContext;
import org.apache.kerby.kerberos.kerb.client.request.KdcRequest;
import org.apache.kerby.kerberos.kerb.preauth.PaFlag;
import org.apache.kerby.kerberos.kerb.preauth.PaFlags;
import org.apache.kerby.kerberos.kerb.preauth.pkinit.PkinitIdenity;
import org.apache.kerby.kerberos.kerb.preauth.pkinit.PkinitPreauthMeta;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.spec.KerberosTime;
import org.apache.kerby.kerberos.kerb.spec.common.EncryptionKey;
import org.apache.kerby.kerberos.kerb.spec.common.EncryptionType;
import org.apache.kerby.kerberos.kerb.spec.common.PrincipalName;
import org.apache.kerby.kerberos.kerb.spec.pa.PaData;
import org.apache.kerby.kerberos.kerb.spec.pa.PaDataEntry;
import org.apache.kerby.kerberos.kerb.spec.pa.PaDataType;
import org.apache.kerby.kerberos.kerb.spec.pa.pkinit.*;
import org.apache.kerby.kerberos.kerb.spec.x509.SubjectPublicKeyInfo;

public class PkinitPreauth extends AbstractPreauthPlugin {

    private PkinitContext pkinitContext;

    public PkinitPreauth() {
        super(new PkinitPreauthMeta());
    }

    @Override
    public void init(KrbContext context) {
        super.init(context);
        this.pkinitContext = new PkinitContext();
    }

    @Override
    public PluginRequestContext initRequestContext(KdcRequest kdcRequest) {
        PkinitRequestContext reqCtx = new PkinitRequestContext();

        reqCtx.updateRequestOpts(pkinitContext.pluginOpts);

        return reqCtx;
    }

    @Override
    public void setPreauthOptions(KdcRequest kdcRequest,
                                  PluginRequestContext requestContext,
                                  KrbOptions options) {
        if (options.contains(KrbOption.PKINIT_X509_IDENTITY)) {
            pkinitContext.identityOpts.identity =
                    options.getStringOption(KrbOption.PKINIT_X509_IDENTITY);
        }

        if (options.contains(KrbOption.PKINIT_X509_ANCHORS)) {
            pkinitContext.identityOpts.anchors.add(
                    options.getStringOption(KrbOption.PKINIT_X509_ANCHORS));
        }

        if (options.contains(KrbOption.PKINIT_USING_RSA)) {
            pkinitContext.pluginOpts.usingRsa =
                    options.getBooleanOption(KrbOption.PKINIT_USING_RSA);
        }

    }

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

    public void tryFirst(KdcRequest kdcRequest,
                         PluginRequestContext requestContext,
                         PaData outPadata) throws KrbException {

    }

    @Override
    public boolean process(KdcRequest kdcRequest,
                        PluginRequestContext requestContext,
                        PaDataEntry inPadata,
                        PaData outPadata) throws KrbException {

        PkinitRequestContext reqCtx = (PkinitRequestContext) requestContext;
        if (inPadata == null) return false;

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

    private PaPkAsReq makePaPkAsReq(PkinitContext pkinitContext, PkinitRequestContext reqCtx,
                                    KerberosTime ctime, int cusec, int nonce, byte[] checksum,
                                    PrincipalName client, PrincipalName server) {

        PaPkAsReq paPkAsReq = new PaPkAsReq();
        AuthPack authPack = new AuthPack();
        SubjectPublicKeyInfo pubInfo = new SubjectPublicKeyInfo();
        PkAuthenticator pkAuthen = new PkAuthenticator();

        boolean usingRsa = reqCtx.requestOpts.usingRsa;
        PaDataType paType = reqCtx.paType = PaDataType.PK_AS_REQ;

        pkAuthen.setCtime(ctime);
        pkAuthen.setCusec(cusec);
        pkAuthen.setNonce(nonce);
        pkAuthen.setPaChecksum(checksum);

        authPack.setPkAuthenticator(pkAuthen);
        DHNonce dhNonce = new DHNonce();
        authPack.setClientDhNonce(dhNonce);
        authPack.setClientPublicValue(pubInfo);

        authPack.setsupportedCmsTypes(pkinitContext.pluginOpts.createSupportedCMSTypes());

        if (usingRsa) {
            // DH case
        } else {
            authPack.setClientPublicValue(null);
        }

        byte[] signedAuthPack = signAuthPack(pkinitContext, reqCtx, authPack);
        paPkAsReq.setSignedAuthPack(signedAuthPack);

        TrustedCertifiers trustedCertifiers = pkinitContext.pluginOpts.createTrustedCertifiers();
        paPkAsReq.setTrustedCertifiers(trustedCertifiers);

        byte[] kdcPkId = pkinitContext.pluginOpts.createIssuerAndSerial();
        paPkAsReq.setKdcPkId(kdcPkId);

        return paPkAsReq;
    }

    private byte[] signAuthPack(PkinitContext pkinitContext,
                                   PkinitRequestContext reqCtx, AuthPack authPack) {
        return null;
    }

    private void processReply(KdcRequest kdcRequest,
                              PkinitRequestContext reqCtx,
                              PaDataEntry inPadata,
                              EncryptionType encType) {

        EncryptionKey asKey = null;

        // TODO

        kdcRequest.setAsKey(asKey);
    }

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
            switch (pde.getPaDataType()) {
                // TODO
            }
        }

        if (doAgain) {
            generateRequest(reqCtx, kdcRequest, outPadata);
        }

        return false;
    }

    @Override
    public PaFlags getFlags(PaDataType paType) {
        PaFlags paFlags = new PaFlags(0);
        paFlags.setFlag(PaFlag.PA_REAL);

        return paFlags;
    }

}
