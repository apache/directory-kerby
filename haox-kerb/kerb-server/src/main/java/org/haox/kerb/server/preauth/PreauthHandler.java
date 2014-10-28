package org.haox.kerb.server.preauth;

import org.haox.kerb.server.KdcContext;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.pa.PaData;

import java.util.ArrayList;
import java.util.List;

public class PreauthHandler {

    private List<KdcPreauth> preauths;

    public void init(KdcContext context) {
        preauths = new ArrayList<KdcPreauth>();

        KdcPreauth preauth = new TimestampPreauth();
        preauth.init(context);
        preauths.add(preauth);
    }

    public void tryFirst(PreauthContext preauthContext, PaData paData) throws KrbException {
        for (KdcPreauth preauth : preauths) {
            //preauth.tryFirst(preauthContext, paData);
        }
    }

    public void process(PreauthContext preauthContext, PaData paData) throws KrbException {
        for (KdcPreauth preauth : preauths) {
            //preauth.process(preauthContext, paData);
        }
    }

    public void tryAgain(PreauthContext preauthContext, PaData paData) {
        for (KdcPreauth preauth : preauths) {
            //preauth.tryAgain(preauthContext, paData);
        }
    }

    public void destroy() {
        for (KdcPreauth preauth : preauths) {
            preauth.destroy();
        }
    }
}
