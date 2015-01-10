package org.apache.kerberos.kerb.server.preauth;

import org.apache.kerberos.kerb.preauth.PluginRequestContext;
import org.apache.kerberos.kerb.server.request.KdcRequest;
import org.apache.kerberos.kerb.KrbException;
import org.apache.kerberos.kerb.spec.pa.PaData;
import org.apache.kerberos.kerb.spec.pa.PaDataEntry;

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
