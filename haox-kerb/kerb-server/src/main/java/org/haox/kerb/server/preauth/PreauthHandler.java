package org.haox.kerb.server.preauth;

import org.haox.kerb.server.KdcContext;
import org.haox.kerb.server.preauth.builtin.TimestampPreauth;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.pa.PaData;
import org.haox.kerb.spec.type.pa.PaDataEntry;
import org.haox.kerb.spec.type.pa.PaDataType;

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

    public void provideEData(PreauthContext preauthContext) throws KrbException {
        for (KdcPreauth preauth : preauths) {
            preauth.provideEData(preauthContext);
        }
    }

    public void verify(PreauthContext preauthContext, PaData paData) throws KrbException {
        for (PaDataEntry paEntry : paData.getElements()) {
            KdcPreauth preauth = getPreauth(paEntry.getPaDataType());
            if (preauth != null) {
                preauth.verify(preauthContext, paEntry);
            }
        }
    }

    public void providePaData(PreauthContext preauthContext, PaData paData) {
        for (KdcPreauth preauth : preauths) {
            preauth.providePaData(preauthContext, paData);
        }
    }

    public void destroy() {
        for (KdcPreauth preauth : preauths) {
            preauth.destroy();
        }
    }

    private KdcPreauth getPreauth(PaDataType paType) {
        for (KdcPreauth preauth : preauths) {
            for (PaDataType pt : preauth.getPaTypes()) {
                if (pt == paType) {
                    return preauth;
                }
            }
        }

        return null;
    }
}
