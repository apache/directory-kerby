package org.haox.kerb.server.preauth.pkinit;

import org.haox.kerb.preauth.PluginRequestContext;
import org.haox.kerb.preauth.pkinit.PkinitPreauthMeta;
import org.haox.kerb.server.preauth.AbstractPreauthPlugin;
import org.haox.kerb.server.request.KdcRequest;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.pa.PaDataEntry;

public class PkinitPreauth extends AbstractPreauthPlugin {

    public PkinitPreauth() {
        super(new PkinitPreauthMeta());
    }

    @Override
    public void verify(KdcRequest kdcRequest, PluginRequestContext requestContext,
                       PaDataEntry paData) throws KrbException {

    }

}
