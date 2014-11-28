package org.haox.kerb.client.preauth.builtin;

import org.haox.kerb.client.KrbContext;
import org.haox.kerb.client.KrbOptions;
import org.haox.kerb.client.preauth.KrbPreauth;
import org.haox.kerb.client.preauth.PluginRequestContext;
import org.haox.kerb.client.preauth.PreauthCallback;
import org.haox.kerb.client.request.KdcRequest;
import org.haox.kerb.client.request.TgsRequest;
import org.haox.kerb.preauth.PaFlag;
import org.haox.kerb.preauth.PaFlags;
import org.haox.kerb.preauth.builtin.TgtPreauthBase;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.common.EncryptionType;
import org.haox.kerb.spec.type.pa.PaData;
import org.haox.kerb.spec.type.pa.PaDataEntry;
import org.haox.kerb.spec.type.pa.PaDataType;

import java.util.Collections;
import java.util.List;

public class TgtPreauth extends TgtPreauthBase implements KrbPreauth {

    private KrbContext context;

    public void init(KrbContext context) {
        this.context = context;
    }

    @Override
    public PluginRequestContext initRequestContext(KrbContext krbContext,
                                                    KdcRequest kdcRequest,
                                                    PreauthCallback preauthCallback) {
        return null;
    }

    @Override
    public void prepareQuestions(KrbContext krbContext,
                                 KdcRequest kdcRequest,
                                 PreauthCallback preauthCallback,
                                 PluginRequestContext requestContext) throws KrbException {


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
        
    }

    public void tryFirst(KrbContext krbContext,
                         KdcRequest kdcRequest,
                         PreauthCallback preauthCallback,
                         PluginRequestContext requestContext,
                         PaData outPadata) throws KrbException {

        outPadata.addElement(makeEntry(krbContext, kdcRequest, preauthCallback));
    }

    @Override
    public boolean process(KrbContext krbContext,
                        KdcRequest kdcRequest,
                        PreauthCallback preauthCallback,
                        PluginRequestContext requestContext,
                        PaDataEntry inPadata,
                        PaData outPadata) throws KrbException {

        outPadata.addElement(makeEntry(krbContext, kdcRequest, preauthCallback));

        return true;
    }

    @Override
    public boolean tryAgain(KrbContext krbContext,
                         KdcRequest kdcRequest,
                         PreauthCallback preauthCallback,
                         PluginRequestContext requestContext,
                         PaDataType preauthType,
                         PaData errPadata,
                         PaData outPadata) {
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

    private PaDataEntry makeEntry(KrbContext krbContext,
                                  KdcRequest kdcRequest,
                                  PreauthCallback preauthCallback) throws KrbException {

        TgsRequest tgsRequest = (TgsRequest) kdcRequest;

        PaDataEntry paEntry = new PaDataEntry();
        paEntry.setPaDataType(PaDataType.TGS_REQ);
        paEntry.setPaDataValue(tgsRequest.getApReq().encode());

        return paEntry;
    }
}
