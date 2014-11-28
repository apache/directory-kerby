package org.haox.kerb.client.preauth.pkinit;

import org.haox.kerb.client.KrbContext;
import org.haox.kerb.client.KrbOption;
import org.haox.kerb.client.KrbOptions;
import org.haox.kerb.client.preauth.KrbPreauth;
import org.haox.kerb.client.preauth.PluginRequestContext;
import org.haox.kerb.client.preauth.PreauthCallback;
import org.haox.kerb.client.request.KdcRequest;
import org.haox.kerb.preauth.PaFlag;
import org.haox.kerb.preauth.PaFlags;
import org.haox.kerb.preauth.pkinit.PkinitIdenity;
import org.haox.kerb.preauth.pkinit.PkinitPreauthBase;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.common.EncryptionKey;
import org.haox.kerb.spec.type.common.EncryptionType;
import org.haox.kerb.spec.type.pa.PaData;
import org.haox.kerb.spec.type.pa.PaDataEntry;
import org.haox.kerb.spec.type.pa.PaDataType;

import java.util.Collections;
import java.util.List;

public class PkinitPreauth extends PkinitPreauthBase implements KrbPreauth {

    private KrbContext context;
    private PkinitContext pkinitContext;

    public void init(KrbContext context) {
        this.context = context;
        this.pkinitContext = new PkinitContext();
    }

    @Override
    public PluginRequestContext initRequestContext(KrbContext krbContext,
                                                    KdcRequest kdcRequest,
                                                    PreauthCallback preauthCallback) {
        PkinitRequestContext reqCtx = new PkinitRequestContext();

        reqCtx.updateRequestOpts(pkinitContext.pluginOpts);

        return reqCtx;
    }

    @Override
    public List<EncryptionType> getEncTypes(KrbContext krbContext,
                                            KdcRequest kdcRequest,
                                            PreauthCallback preauthCallback,
                                            PluginRequestContext requestContext) {
        return Collections.emptyList();
    }

    @Override
    public void setPreauthOptions(KrbContext krbContext,
                                  KdcRequest kdcRequest,
                                  PreauthCallback preauthCallback,
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
    public void prepareQuestions(KrbContext krbContext,
                                 KdcRequest kdcRequest,
                                 PreauthCallback preauthCallback,
                                 PluginRequestContext requestContext) {

        PkinitRequestContext reqCtx = (PkinitRequestContext) requestContext;

        if (!reqCtx.identityInitialized) {
            PkinitIdenity.initialize(reqCtx.identityOpts, kdcRequest.getClientPrincipal());
            reqCtx.identityInitialized = true;
        }

        // Might have questions asking for password to access the private key
    }

    public void tryFirst(KrbContext krbContext,
                         KdcRequest kdcRequest,
                         PreauthCallback preauthCallback,
                         PluginRequestContext requestContext,
                         PaData outPadata) throws KrbException {

    }

    @Override
    public boolean process(KrbContext krbContext,
                        KdcRequest kdcRequest,
                        PreauthCallback preauthCallback,
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
            generateRequest(reqCtx, outPadata);
        } else {
            EncryptionType encType = preauthCallback.getEncType(krbContext, kdcRequest);
            processReply(krbContext, kdcRequest, preauthCallback, reqCtx, inPadata, encType);
        }

        return false;
    }

    private void generateRequest(PkinitRequestContext reqCtx, PaData outPadata) {

    }

    private void processReply(KrbContext krbContext,
                              KdcRequest kdcRequest,
                              PreauthCallback preauthCallback,
                              PkinitRequestContext reqCtx,
                              PaDataEntry inPadata,
                              EncryptionType encType) {

        EncryptionKey asKey = null;

        // TODO

        preauthCallback.setAsKey(krbContext, kdcRequest, asKey);
    }

    @Override
    public boolean tryAgain(KrbContext krbContext,
                         KdcRequest kdcRequest,
                         PreauthCallback preauthCallback,
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
            generateRequest(reqCtx, outPadata);
        }

        return false;
    }

    @Override
    public PaFlags getFlags(KrbContext krbContext,
                            PaDataType paType) {
        PaFlags paFlags = new PaFlags(0);
        paFlags.setFlag(PaFlag.PA_REAL);

        return paFlags;
    }

    @Override
    public void destroy(KrbContext krbContext) {

    }

}
