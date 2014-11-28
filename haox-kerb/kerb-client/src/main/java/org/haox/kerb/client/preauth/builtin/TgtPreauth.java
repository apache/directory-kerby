package org.haox.kerb.client.preauth.builtin;

import org.haox.kerb.client.KrbContext;
import org.haox.kerb.client.preauth.AbstractPreauthPlugin;
import org.haox.kerb.client.preauth.PluginRequestContext;
import org.haox.kerb.client.preauth.PreauthCallback;
import org.haox.kerb.client.request.KdcRequest;
import org.haox.kerb.client.request.TgsRequest;
import org.haox.kerb.preauth.builtin.TgtPreauthMeta;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.pa.PaData;
import org.haox.kerb.spec.type.pa.PaDataEntry;
import org.haox.kerb.spec.type.pa.PaDataType;

public class TgtPreauth extends AbstractPreauthPlugin {

    public TgtPreauth() {
        super(new TgtPreauthMeta());
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
