package org.haox.kerb.server.preauth.pkinit;

import org.haox.kerb.preauth.PluginRequestContext;
import org.haox.kerb.preauth.pkinit.PkinitPreauthMeta;
import org.haox.kerb.server.KdcContext;
import org.haox.kerb.server.preauth.AbstractPreauthPlugin;
import org.haox.kerb.server.request.KdcRequest;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.common.PrincipalName;
import org.haox.kerb.spec.type.pa.PaDataEntry;

import java.util.HashMap;
import java.util.Map;

public class PkinitPreauth extends AbstractPreauthPlugin {

    private Map<String, PkinitKdcContext> pkinitContexts;

    public PkinitPreauth() {
        super(new PkinitPreauthMeta());

        pkinitContexts = new HashMap<String, PkinitKdcContext>(1);
    }

    @Override
    public void initWith(KdcContext kdcContext) {
        super.initWith(kdcContext);

        PkinitKdcContext tmp = new PkinitKdcContext();
        tmp.realm = kdcContext.getKdcRealm();
        pkinitContexts.put(kdcContext.getKdcRealm(), tmp);
    }

    @Override
    public PluginRequestContext initRequestContext(KdcRequest kdcRequest) {
        PkinitRequestContext reqCtx = new PkinitRequestContext();

        //reqCtx.updateRequestOpts(pkinitContext.pluginOpts);

        return reqCtx;
    }

    @Override
    public boolean verify(KdcRequest kdcRequest, PluginRequestContext requestContext,
                          PaDataEntry paData) throws KrbException {

        PkinitKdcContext pkinitContext = findContext(kdcRequest.getServerPrincipal());
        if (pkinitContext == null) {
            return false;
        }

        return true;
    }

    private PkinitKdcContext findContext(PrincipalName principal) {
        String realm = principal.getRealm();
        if (pkinitContexts.containsKey(realm)) {
            return pkinitContexts.get(realm);
        }
        return null;
    }
}
