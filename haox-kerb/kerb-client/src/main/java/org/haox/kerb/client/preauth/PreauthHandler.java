package org.haox.kerb.client.preauth;

import org.haox.kerb.client.KrbContext;
import org.haox.kerb.client.KrbOptions;
import org.haox.kerb.client.preauth.pkinit.PkinitPreauth;
import org.haox.kerb.client.preauth.token.TokenPreauth;
import org.haox.kerb.client.request.KdcRequest;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.pa.PaData;
import org.haox.kerb.spec.type.pa.PaDataEntry;
import org.haox.kerb.spec.type.pa.PaDataType;

import java.util.ArrayList;
import java.util.List;

public class PreauthHandler {

    private List<KrbPreauth> preauths;
    private PreauthCallback preauthCallback;

    public void init(KrbContext krbContext) {
        preauthCallback = new PreauthCallback();
        loadPreauthPlugins(krbContext);
    }

    private void loadPreauthPlugins(KrbContext context) {
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

    public PreauthContext preparePreauthContext(KrbContext krbContext, KdcRequest kdcRequest) {
        PreauthContext preauthContext = new PreauthContext();

        for (KrbPreauth preauth : preauths) {
            PreauthHandle handle = new PreauthHandle();
            handle.preauth = preauth;
            handle.requestContext = preauth.initRequestContext(
                    krbContext, kdcRequest, preauthCallback);
            preauthContext.handles.add(handle);
        }

        return preauthContext;
    }

    public void setPreauthOptions(KrbContext krbContext, KdcRequest kdcRequest,
                                  KrbOptions preauthOptions) throws KrbException {
        for (PreauthHandle handle : kdcRequest.getPreauthContext().handles) {
            handle.setPreauthOptions(krbContext, kdcRequest, preauthCallback, preauthOptions);
        }
    }

    public void process(KrbContext krbContext, KdcRequest kdcRequest,
                        PaDataEntry inPadata, PaData outPadata) throws KrbException {
        for (PreauthHandle handle : kdcRequest.getPreauthContext().handles) {
            handle.process(krbContext, kdcRequest, preauthCallback, inPadata, outPadata);
        }
    }

    public void tryAgain(KrbContext krbContext, KdcRequest kdcRequest, PaDataType preauthType,
                         PaData errPadata, PaData outPadata) {
        for (PreauthHandle handle : kdcRequest.getPreauthContext().handles) {
            handle.tryAgain(krbContext, kdcRequest, preauthCallback,
                    preauthType, errPadata, outPadata);
        }
    }

    public void destroy(KrbContext krbContext) {
        for (KrbPreauth preauth : preauths) {
            preauth.destroy(krbContext);
        }
    }

}
