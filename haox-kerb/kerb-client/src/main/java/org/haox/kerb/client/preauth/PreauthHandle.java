package org.haox.kerb.client.preauth;

import org.haox.kerb.client.KrbOptions;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.pa.PaData;

public class PreauthHandle {

    public KrbPreauth preauth;
    public PreauthRequestContext requestContext;

    public void setPreauthOptions(PreauthCallback preauthCallback,
                                  KrbOptions preauthOptions) throws KrbException {
        preauth.setPreauthOptions(preauthCallback, requestContext, preauthOptions);
    }

    public void tryFirst(PreauthCallback preauthCallback, PaData paData) throws KrbException {
        preauth.tryFirst(preauthCallback, requestContext, paData);
    }

    public void process(PreauthCallback preauthCallback, PaData paData) throws KrbException {
        preauth.process(preauthCallback, requestContext, paData);
    }

    public void tryAgain(PreauthCallback preauthCallback, PaData paData) {
        preauth.tryAgain(preauthCallback, requestContext, paData);
    }

}
