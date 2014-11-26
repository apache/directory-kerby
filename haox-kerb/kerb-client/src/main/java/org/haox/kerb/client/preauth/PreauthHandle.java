package org.haox.kerb.client.preauth;

import org.haox.kerb.client.KrbContext;
import org.haox.kerb.client.KrbOptions;
import org.haox.kerb.client.request.KdcRequest;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.pa.PaData;
import org.haox.kerb.spec.type.pa.PaDataEntry;
import org.haox.kerb.spec.type.pa.PaDataType;

public class PreauthHandle {

    public KrbPreauth preauth;
    public PluginRequestContext requestContext;

    public void setPreauthOptions(KrbContext krbContext, KdcRequest kdcRequest,
                                  PreauthCallback preauthCallback,
                                  KrbOptions preauthOptions) throws KrbException {
        preauth.setPreauthOptions(krbContext, kdcRequest,
                preauthCallback, requestContext, preauthOptions);
    }

    public void process(KrbContext krbContext, KdcRequest kdcRequest,
                        PreauthCallback preauthCallback,
                        PaDataEntry inPadata, PaData outPadata) throws KrbException {
        preauth.process(krbContext, kdcRequest,
                preauthCallback, requestContext, inPadata, outPadata);
    }

    public void tryAgain(KrbContext krbContext, KdcRequest kdcRequest,
                         PreauthCallback preauthCallback,
                         PaDataType preauthType, PaData errPadata, PaData paData) {
        preauth.tryAgain(krbContext, kdcRequest,
                preauthCallback, requestContext, preauthType, errPadata, paData);
    }

}
