package org.apache.kerberos.kerb.server.preauth.pkinit;

import org.apache.kerberos.kerb.codec.KrbCodec;
import org.apache.kerberos.kerb.preauth.PluginRequestContext;
import org.apache.kerberos.kerb.preauth.pkinit.PkinitPreauthMeta;
import org.apache.kerberos.kerb.server.KdcContext;
import org.apache.kerberos.kerb.server.preauth.AbstractPreauthPlugin;
import org.apache.kerberos.kerb.server.request.KdcRequest;
import org.apache.kerberos.kerb.KrbException;
import org.apache.kerberos.kerb.spec.common.PrincipalName;
import org.apache.kerberos.kerb.spec.pa.PaDataEntry;
import org.apache.kerberos.kerb.spec.pa.PaDataType;
import org.apache.kerberos.kerb.spec.pa.pkinit.PaPkAsReq;

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

        PkinitRequestContext reqCtx = (PkinitRequestContext) requestContext;
        PkinitKdcContext pkinitContext = findContext(kdcRequest.getServerPrincipal());
        if (pkinitContext == null) {
            return false;
        }

        reqCtx.paType = paData.getPaDataType();
        if (paData.getPaDataType() == PaDataType.PK_AS_REQ) {
            PaPkAsReq paPkAsReq = KrbCodec.decode(paData.getPaDataValue(), PaPkAsReq.class);
            if (paPkAsReq == null) {
                return false;
            }
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
