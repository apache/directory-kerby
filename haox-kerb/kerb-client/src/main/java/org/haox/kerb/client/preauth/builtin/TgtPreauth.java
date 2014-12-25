package org.haox.kerb.client.preauth.builtin;

import org.haox.kerb.client.preauth.AbstractPreauthPlugin;
import org.haox.kerb.client.request.KdcRequest;
import org.haox.kerb.client.request.TgsRequest;
import org.haox.kerb.preauth.PluginRequestContext;
import org.haox.kerb.preauth.builtin.TgtPreauthMeta;
import org.haox.kerb.KrbException;
import org.haox.kerb.spec.pa.PaData;
import org.haox.kerb.spec.pa.PaDataEntry;
import org.haox.kerb.spec.pa.PaDataType;

public class TgtPreauth extends AbstractPreauthPlugin {

    public TgtPreauth() {
        super(new TgtPreauthMeta());
    }

    public void tryFirst(KdcRequest kdcRequest,
                         PluginRequestContext requestContext,
                         PaData outPadata) throws KrbException {

        outPadata.addElement(makeEntry(kdcRequest));
    }

    @Override
    public boolean process(KdcRequest kdcRequest,
                        PluginRequestContext requestContext,
                        PaDataEntry inPadata,
                        PaData outPadata) throws KrbException {

        outPadata.addElement(makeEntry(kdcRequest));

        return true;
    }

    private PaDataEntry makeEntry(KdcRequest kdcRequest) throws KrbException {

        TgsRequest tgsRequest = (TgsRequest) kdcRequest;

        PaDataEntry paEntry = new PaDataEntry();
        paEntry.setPaDataType(PaDataType.TGS_REQ);
        paEntry.setPaDataValue(tgsRequest.getApReq().encode());

        return paEntry;
    }
}
