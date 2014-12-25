package org.apache.kerberos.kerb.client.preauth.builtin;

import org.apache.kerberos.kerb.client.preauth.AbstractPreauthPlugin;
import org.apache.kerberos.kerb.client.request.KdcRequest;
import org.apache.kerberos.kerb.client.request.TgsRequest;
import org.apache.kerberos.kerb.preauth.PluginRequestContext;
import org.apache.kerberos.kerb.preauth.builtin.TgtPreauthMeta;
import org.apache.kerberos.kerb.KrbException;
import org.apache.kerberos.kerb.spec.pa.PaData;
import org.apache.kerberos.kerb.spec.pa.PaDataEntry;
import org.apache.kerberos.kerb.spec.pa.PaDataType;

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
