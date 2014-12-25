package org.haox.kerb.server.preauth.builtin;

import org.haox.kerb.preauth.PluginRequestContext;
import org.haox.kerb.preauth.builtin.TgtPreauthMeta;
import org.haox.kerb.server.preauth.AbstractPreauthPlugin;
import org.haox.kerb.server.request.KdcRequest;
import org.haox.kerb.server.request.TgsRequest;
import org.haox.kerb.KrbException;
import org.haox.kerb.spec.pa.PaDataEntry;

public class TgtPreauth extends AbstractPreauthPlugin {

    public TgtPreauth() {
        super(new TgtPreauthMeta());
    }

    @Override
    public boolean verify(KdcRequest kdcRequest, PluginRequestContext requestContext,
                          PaDataEntry paData) throws KrbException {

        TgsRequest tgsRequest = (TgsRequest) kdcRequest;
        tgsRequest.verifyAuthenticator(paData);
        return true;
    }

}
