package org.haox.kerb.server.preauth;

import org.haox.kerb.preauth.PluginRequestContext;
import org.haox.kerb.server.request.KdcRequest;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.pa.PaData;
import org.haox.kerb.spec.type.pa.PaDataEntry;

public class PreauthHandle {

    public KdcPreauth preauth;
    public PluginRequestContext requestContext;

    public PreauthHandle(KdcPreauth preauth) {
        this.preauth = preauth;
    }

    public void initRequestContext(KdcRequest kdcRequest) {
        requestContext = preauth.initRequestContext(kdcRequest);
    }

    public void provideEdata(KdcRequest kdcRequest, PaData outPaData) throws KrbException {
        preauth.provideEdata(kdcRequest, requestContext, outPaData);
    }

    public void verify(KdcRequest kdcRequest, PaDataEntry paData) throws KrbException {
        preauth.verify(kdcRequest, requestContext, paData);
    }

    public void providePaData(KdcRequest kdcRequest, PaData paData) {
        preauth.providePaData(kdcRequest, requestContext, paData);
    }

    public void destroy() {
        preauth.destroy();
    }
}
