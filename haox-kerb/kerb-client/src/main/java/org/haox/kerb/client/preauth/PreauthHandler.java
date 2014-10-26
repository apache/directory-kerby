package org.haox.kerb.client.preauth;

import org.haox.kerb.client.KrbContext;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.pa.PaData;

import java.util.ArrayList;
import java.util.List;

public class PreauthHandler {

    private List<Preauth> preauths;

    public void init(KrbContext context) {
        preauths = new ArrayList<Preauth>();

        Preauth preauth = new TimestampPreauth();
        preauth.init(context);
        preauths.add(preauth);
    }

    public void tryFirst(PreauthContext preauthContext, PaData paData) throws KrbException {
        for (Preauth preauth : preauths) {
            preauth.tryFirst(preauthContext, paData);
        }
    }

    public void process(PreauthContext preauthContext, PaData paData) throws KrbException {
        for (Preauth preauth : preauths) {
            preauth.process(preauthContext, paData);
        }
    }

    public void tryAgain(PreauthContext preauthContext, PaData paData) {
        for (Preauth preauth : preauths) {
            preauth.tryAgain(preauthContext, paData);
        }
    }

    public void destroy(KrbContext context) {
        for (Preauth preauth : preauths) {
            preauth.destroy(context);
        }
    }
}
