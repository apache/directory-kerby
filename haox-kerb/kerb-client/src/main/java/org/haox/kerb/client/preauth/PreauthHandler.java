package org.haox.kerb.client.preauth;

import org.haox.kerb.client.KrbContext;
import org.haox.kerb.client.KrbOptions;
import org.haox.kerb.client.preauth.builtin.EncTsPreauth;
import org.haox.kerb.client.preauth.builtin.TgtPreauth;
import org.haox.kerb.client.preauth.pkinit.PkinitPreauth;
import org.haox.kerb.client.preauth.token.TokenPreauth;
import org.haox.kerb.client.request.KdcRequest;
import org.haox.kerb.codec.KrbCodec;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.common.EtypeInfo;
import org.haox.kerb.spec.type.common.EtypeInfo2;
import org.haox.kerb.spec.type.pa.PaData;
import org.haox.kerb.spec.type.pa.PaDataEntry;
import org.haox.kerb.spec.type.pa.PaDataType;

import java.util.ArrayList;
import java.util.List;

public class PreauthHandler {

    private List<KrbPreauth> preauths;
    private PreauthCallback preauthCallback;

    public void init(KrbContext krbContext) {
        preauthCallback = new PreauthCallback();
        loadPreauthPlugins(krbContext);
    }

    private void loadPreauthPlugins(KrbContext context) {
        preauths = new ArrayList<KrbPreauth>();

        KrbPreauth preauth = new EncTsPreauth();
        preauth.init(context);
        preauths.add(preauth);

        preauth = new TgtPreauth();
        preauth.init(context);
        preauths.add(preauth);

        preauth = new PkinitPreauth();
        preauth.init(context);
        preauths.add(preauth);

        preauth = new TokenPreauth();
        preauth.init(context);
        preauths.add(preauth);
    }

    public PreauthContext preparePreauthContext(KrbContext krbContext, KdcRequest kdcRequest) {
        PreauthContext preauthContext = new PreauthContext();

        for (KrbPreauth preauth : preauths) {
            PreauthHandle handle = new PreauthHandle();
            handle.preauth = preauth;
            handle.requestContext = preauth.initRequestContext(
                    krbContext, kdcRequest, preauthCallback);
            preauthContext.getHandles().add(handle);
        }

        return preauthContext;
    }

    /**
     * Process preauth inputs and options, prepare and generate pdata to be out
     */
    public void preauth(KrbContext krbContext, KdcRequest kdcRequest) throws KrbException {
        PreauthContext preauthContext = kdcRequest.getPreauthContext();

        if (!preauthContext.isPreauthRequired()) {
            return;
        }

        if (!preauthContext.hasInputPaData()) {
            tryFirst(krbContext, kdcRequest, preauthContext.getOutputPaData());
            return;
        }

        attemptETypeInfo(krbContext, kdcRequest, preauthContext.getInputPaData());

        setPreauthOptions(krbContext, kdcRequest, kdcRequest.getPreauthOptions());

        prepareUserResponses(krbContext, kdcRequest, preauthContext.getInputPaData());

        preauthContext.getUserResponser().respondQuestions();

        if (!kdcRequest.isRetrying()) {
            process(krbContext, kdcRequest, preauthContext.getInputPaData(),
                    preauthContext.getOutputPaData());
        } else {
            tryAgain(krbContext, kdcRequest, preauthContext.getInputPaData(),
                    preauthContext.getOutputPaData());
        }
    }

    public void prepareUserResponses(KrbContext krbContext, KdcRequest kdcRequest,
                                     PaData inPadata) throws KrbException {
        PreauthContext preauthContext = kdcRequest.getPreauthContext();

        for (PaDataEntry pae : inPadata.getElements()) {
            if (! preauthContext.isPaTypeAllowed(pae.getPaDataType())) {
                continue;
            }

            PreauthHandle handle = findHandle(krbContext, kdcRequest, pae.getPaDataType());
            if (handle == null) {
                continue;
            }

            handle.prepareQuestions(krbContext, kdcRequest, preauthCallback);
        }
    }

    public void setPreauthOptions(KrbContext krbContext, KdcRequest kdcRequest,
                                  KrbOptions preauthOptions) throws KrbException {
        PreauthContext preauthContext = kdcRequest.getPreauthContext();

        for (PreauthHandle handle : preauthContext.getHandles()) {
            handle.setPreauthOptions(krbContext, kdcRequest, preauthCallback, preauthOptions);
        }
    }

    public void tryFirst(KrbContext krbContext, KdcRequest kdcRequest,
                         PaData outPadata) throws KrbException {
        PreauthContext preauthContext = kdcRequest.getPreauthContext();

        PreauthHandle handle = findHandle(krbContext, kdcRequest,
                preauthContext.getAllowedPaType());
        handle.tryFirst(krbContext, kdcRequest, preauthCallback, outPadata);
    }

    public void process(KrbContext krbContext, KdcRequest kdcRequest,
                        PaData inPadata, PaData outPadata) throws KrbException {
        PreauthContext preauthContext = kdcRequest.getPreauthContext();

        /**
         * Process all informational padata types, then the first real preauth type
         * we succeed on
         */
        for (int real = 0; real <= 1; real ++) {
            for (PaDataEntry pae : inPadata.getElements()) {

                // Restrict real mechanisms to the chosen one if we have one
                if (real >0 && !preauthContext.isPaTypeAllowed(pae.getPaDataType())) {
                    continue;
                }

                PreauthHandle handle = findHandle(krbContext, kdcRequest,
                        preauthContext.getAllowedPaType());
                if (handle == null) {
                    continue;
                }

                // Make sure this type is for the current pass
                int tmpReal = handle.isReal(krbContext, pae.getPaDataType()) ? 1 : 0;
                if (tmpReal != real) {
                    continue;
                }

                if (real > 0 && preauthContext.checkAndPutTried(pae.getPaDataType())) {
                    continue;
                }

                boolean gotData = handle.process(krbContext, kdcRequest,
                        preauthCallback, pae, outPadata);
                if (real > 0 && gotData) {
                    return;
                }
            }
        }
    }

    public void tryAgain(KrbContext krbContext, KdcRequest kdcRequest,
                         PaData inPadata, PaData outPadata) {
        PreauthContext preauthContext = kdcRequest.getPreauthContext();

        PreauthHandle handle;
        for (PaDataEntry pae : inPadata.getElements()) {
            handle = findHandle(krbContext, kdcRequest, pae.getPaDataType());
            if (handle == null) continue;

            boolean gotData = handle.tryAgain(krbContext, kdcRequest, preauthCallback,
                    pae.getPaDataType(), preauthContext.getErrorPaData(), outPadata);
        }
    }

    public void destroy(KrbContext krbContext) {
        for (KrbPreauth preauth : preauths) {
            preauth.destroy(krbContext);
        }
    }

    private PreauthHandle findHandle(KrbContext krbContext, KdcRequest kdcRequest,
                                     PaDataType paType) {
        PreauthContext preauthContext = kdcRequest.getPreauthContext();

        for (PreauthHandle handle : preauthContext.getHandles()) {
            for (PaDataType pt : handle.preauth.getPaTypes()) {
                if (pt == paType) {
                    return handle;
                }
            }
        }
        return null;
    }

    private void attemptETypeInfo(KrbContext krbContext, KdcRequest kdcRequest,
                                  PaData inPadata) throws KrbException {
        PreauthContext preauthContext = kdcRequest.getPreauthContext();

        // Find an etype-info2 or etype-info element in padata
        EtypeInfo etypeInfo = null;
        EtypeInfo2 etypeInfo2 = null;
        PaDataEntry pae = inPadata.findEntry(PaDataType.ETYPE_INFO);
        if (pae != null) {
            etypeInfo = KrbCodec.decode(pae.getPaDataValue(), EtypeInfo.class);
        } else {
            pae = inPadata.findEntry(PaDataType.ETYPE_INFO2);
            if (pae != null) {
                etypeInfo2 = KrbCodec.decode(pae.getPaDataValue(), EtypeInfo2.class);
            }
        }

        if (etypeInfo == null && etypeInfo2 == null) {
            attemptSalt(krbContext, kdcRequest, inPadata);
        }


    }

    private void attemptSalt(KrbContext krbContext, KdcRequest kdcRequest,
                                  PaData inPadata) throws KrbException {

    }
}
