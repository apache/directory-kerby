package org.haox.kerb.client.preauth;

import org.haox.kerb.client.KrbOptions;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.pa.PaData;
import org.haox.kerb.spec.type.pa.PaDataEntry;
import org.haox.kerb.spec.type.pa.PaDataType;

public class PreauthHandle {

    public KrbPreauth preauth;
    public PreauthRequestContext requestContext;

    public void setPreauthOptions(PreauthCallback preauthCallback,
                                  KrbOptions preauthOptions) throws KrbException {
        preauth.setPreauthOptions(preauthCallback, requestContext, preauthOptions);
    }

    public void process(PreauthCallback preauthCallback,
                        PaDataEntry inPadata, PaData outPadata) throws KrbException {
        preauth.process(preauthCallback, requestContext, inPadata, outPadata);
    }

    public void tryAgain(PreauthCallback preauthCallback,
                         PaDataType preauthType, PaData errPadata, PaData paData) {
        preauth.tryAgain(preauthCallback, requestContext, preauthType, errPadata, paData);
    }

}
