package org.haox.kerb.server.preauth;

import org.haox.kerb.preauth.PluginRequestContext;
import org.haox.kerb.server.KdcContext;
import org.haox.kerb.server.preauth.builtin.EncTsPreauth;
import org.haox.kerb.server.request.KdcRequest;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.pa.PaData;
import org.haox.kerb.spec.type.pa.PaDataEntry;
import org.haox.kerb.spec.type.pa.PaDataType;

import java.util.ArrayList;
import java.util.List;

public class PreauthHandler {

    private List<KdcPreauth> preauths;

    public void init(KdcContext context) {
        loadPreauthPlugins(context);
    }

    private void loadPreauthPlugins(KdcContext context) {
        preauths = new ArrayList<KdcPreauth>();

        KdcPreauth preauth = new EncTsPreauth();
        preauth.init(context);
        preauths.add(preauth);
    }

    public PreauthContext preparePreauthContext(KdcRequest kdcRequest) {
        PreauthContext preauthContext = new PreauthContext();

        for (KdcPreauth preauth : preauths) {
            PreauthHandle handle = new PreauthHandle(preauth);
            handle.initRequestContext(kdcRequest);
            preauthContext.getHandles().add(handle);
        }

        return preauthContext;
    }

    public void provideEdata(KdcRequest kdcRequest, PaData outPaData) throws KrbException {
        PreauthContext preauthContext = kdcRequest.getPreauthContext();

        for (PreauthHandle handle : preauthContext.getHandles()) {
            handle.provideEdata(kdcRequest, outPaData);
        }
    }

    public void verify(KdcRequest kdcRequest, PaData paData) throws KrbException {
        for (PaDataEntry paEntry : paData.getElements()) {
            PreauthHandle handle = findHandle(kdcRequest, paEntry.getPaDataType());
            if (handle != null) {
                handle.verify(kdcRequest, paEntry);
            }
        }
    }

    public void providePaData(KdcRequest kdcRequest, PaData paData) {
        PreauthContext preauthContext = kdcRequest.getPreauthContext();

        for (PreauthHandle handle : preauthContext.getHandles()) {
            handle.providePaData(kdcRequest, paData);
        }
    }

    private PreauthHandle findHandle(KdcRequest kdcRequest, PaDataType paType) {
        PreauthContext preauthContext = kdcRequest.getPreauthContext();

        for (PreauthHandle handle : preauthContext.getHandles()) {
            for (PaDataType pt : handle.preauth.getPaTypes()) {
                if (pt == paType) {
                    return handle;
                }
            }
        }
        return null;
    }

    public void destroy() {
        for (KdcPreauth preauth : preauths) {
            preauth.destroy();
        }
    }
}
