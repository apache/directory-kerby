package org.haox.kerb.client.preauth;

import org.haox.kerb.client.KrbContext;
import org.haox.kerb.client.KrbOption;
import org.haox.kerb.client.KrbOptions;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.pa.PaData;

import java.util.ArrayList;
import java.util.List;

public class PreauthHandler {

    private List<KrbPreauth> preauths;

    public void init(KrbContext context) {
        preauths = new ArrayList<KrbPreauth>();

        KrbPreauth preauth = new TimestampPreauth();
        preauth.init(context);
        preauths.add(preauth);

        preauth = new PkinitPreauth();
        preauth.init(context);
        preauths.add(preauth);
    }

    public void setPreauthOptions(KrbOptions preauthOptions) throws KrbException {
        for (KrbPreauth preauth : preauths) {
            preauth.setPreauthOptions(preauthOptions);
        }
    }

    public void tryFirst(PreauthContext preauthContext, PaData paData) throws KrbException {
        for (KrbPreauth preauth : preauths) {
            preauth.tryFirst(preauthContext, paData);
        }
    }

    public void process(PreauthContext preauthContext, PaData paData) throws KrbException {
        for (KrbPreauth preauth : preauths) {
            preauth.process(preauthContext, paData);
        }
    }

    public void tryAgain(PreauthContext preauthContext, PaData paData) {
        for (KrbPreauth preauth : preauths) {
            preauth.tryAgain(preauthContext, paData);
        }
    }

    public void destroy() {
        for (KrbPreauth preauth : preauths) {
            preauth.destroy();
        }
    }
}
