package org.haox.kerb.client.preauth;

import org.haox.kerb.client.KrbContext;
import org.haox.kerb.client.KrbOptions;
import org.haox.kerb.client.preauth.pkinit.PkinitPreauth;
import org.haox.kerb.client.preauth.token.TokenPreauth;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.pa.PaData;
import org.haox.kerb.spec.type.pa.PaDataEntry;
import org.haox.kerb.spec.type.pa.PaDataType;

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

        preauth = new TokenPreauth();
        preauth.init(context);
        preauths.add(preauth);
    }

    public PreauthContext preparePreauthContext(PreauthCallback preauthCallback) {
        PreauthContext preauthContext = new PreauthContext();
        preauthContext.preauthCallback = preauthCallback;

        for (KrbPreauth preauth : preauths) {
            preauthContext.handles.add(initHandle(preauth, preauthCallback));
        }

        return preauthContext;
    }

    private PreauthHandle initHandle(KrbPreauth preauth, PreauthCallback preauthCallback) {
        PreauthHandle handle = new PreauthHandle();
        handle.preauth = preauth;
        handle.requestContext = preauth.initRequestContext(preauthCallback);

        return handle;
    }

    public void setPreauthOptions(PreauthContext preauthContext,
                                  KrbOptions preauthOptions) throws KrbException {
        for (PreauthHandle handle : preauthContext.handles) {
            handle.setPreauthOptions(preauthContext.preauthCallback, preauthOptions);
        }
    }

    public void process(PreauthContext preauthContext,
                        PaDataEntry inPadata, PaData outPadata) throws KrbException {
        for (PreauthHandle handle : preauthContext.handles) {
            handle.process(preauthContext.preauthCallback, inPadata, outPadata);
        }
    }

    public void tryAgain(PreauthContext preauthContext, PaDataType preauthType,
                         PaData errPadata, PaData outPadata) {
        for (PreauthHandle handle : preauthContext.handles) {
            handle.tryAgain(preauthContext.preauthCallback, preauthType, errPadata, outPadata);
        }
    }

    public void destroy() {
        for (KrbPreauth preauth : preauths) {
            preauth.destroy();
        }
    }

}
