package org.apache.kerberos.kerb.server.preauth.builtin;

import org.apache.kerberos.kerb.preauth.PluginRequestContext;
import org.apache.kerberos.kerb.preauth.builtin.TgtPreauthMeta;
import org.apache.kerberos.kerb.server.preauth.AbstractPreauthPlugin;
import org.apache.kerberos.kerb.server.request.KdcRequest;
import org.apache.kerberos.kerb.server.request.TgsRequest;
import org.apache.kerberos.kerb.KrbException;
import org.apache.kerberos.kerb.spec.pa.PaDataEntry;

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
