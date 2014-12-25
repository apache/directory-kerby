package org.haox.kerb.client.preauth;

import org.haox.kerb.client.KrbOptions;
import org.haox.kerb.client.request.KdcRequest;
import org.haox.kerb.preauth.PaFlags;
import org.haox.kerb.preauth.PluginRequestContext;
import org.haox.kerb.KrbException;
import org.haox.kerb.spec.pa.PaData;
import org.haox.kerb.spec.pa.PaDataEntry;
import org.haox.kerb.spec.pa.PaDataType;

public class PreauthHandle {

    public KrbPreauth preauth;
    public PluginRequestContext requestContext;

    public PreauthHandle(KrbPreauth preauth) {
        this.preauth = preauth;
    }

    public void initRequestContext(KdcRequest kdcRequest) {
        requestContext = preauth.initRequestContext(kdcRequest);
    }

    public void prepareQuestions(KdcRequest kdcRequest) throws KrbException {
        preauth.prepareQuestions(kdcRequest, requestContext);
    }

    public void setPreauthOptions(KdcRequest kdcRequest,
                                  KrbOptions preauthOptions) throws KrbException {
        preauth.setPreauthOptions(kdcRequest, requestContext, preauthOptions);
    }

    public void tryFirst(KdcRequest kdcRequest, PaData outPadata) throws KrbException {
        preauth.tryFirst(kdcRequest, requestContext, outPadata);
    }

    public boolean process(KdcRequest kdcRequest,
                        PaDataEntry inPadata, PaData outPadata) throws KrbException {
        return preauth.process(kdcRequest, requestContext, inPadata, outPadata);
    }

    public boolean tryAgain(KdcRequest kdcRequest,
                         PaDataType paType, PaData errPadata, PaData paData) {
        return preauth.tryAgain(kdcRequest, requestContext, paType, errPadata, paData);
    }

    public boolean isReal(PaDataType paType) {
        PaFlags paFlags = preauth.getFlags(paType);
        return paFlags.isReal();
    }

}
