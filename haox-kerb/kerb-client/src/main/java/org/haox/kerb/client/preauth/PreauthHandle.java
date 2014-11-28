package org.haox.kerb.client.preauth;

import org.haox.kerb.client.KrbContext;
import org.haox.kerb.client.KrbOptions;
import org.haox.kerb.client.request.KdcRequest;
import org.haox.kerb.preauth.PaFlags;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.pa.PaData;
import org.haox.kerb.spec.type.pa.PaDataEntry;
import org.haox.kerb.spec.type.pa.PaDataType;

public class PreauthHandle {

    public KrbPreauth preauth;
    public PluginRequestContext requestContext;

    public void prepareQuestions(KrbContext krbContext, KdcRequest kdcRequest) throws KrbException {
        preauth.prepareQuestions(krbContext, kdcRequest, requestContext);
    }

    public void setPreauthOptions(KrbContext krbContext, KdcRequest kdcRequest,
                                  KrbOptions preauthOptions) throws KrbException {
        preauth.setPreauthOptions(krbContext, kdcRequest, requestContext, preauthOptions);
    }

    public void tryFirst(KrbContext krbContext, KdcRequest kdcRequest, PaData outPadata) throws KrbException {
        preauth.tryFirst(krbContext, kdcRequest, requestContext, outPadata);
    }

    public boolean process(KrbContext krbContext, KdcRequest kdcRequest,
                        PaDataEntry inPadata, PaData outPadata) throws KrbException {
        return preauth.process(krbContext, kdcRequest, requestContext, inPadata, outPadata);
    }

    public boolean tryAgain(KrbContext krbContext, KdcRequest kdcRequest,
                         PaDataType paType, PaData errPadata, PaData paData) {
        return preauth.tryAgain(krbContext, kdcRequest, requestContext, paType, errPadata, paData);
    }

    public boolean isReal(KrbContext krbContext, PaDataType paType) {
        PaFlags paFlags = preauth.getFlags(krbContext, paType);
        return paFlags.isReal();
    }

}
