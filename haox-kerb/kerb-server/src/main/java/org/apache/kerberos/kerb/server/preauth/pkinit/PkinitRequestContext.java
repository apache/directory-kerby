package org.apache.kerberos.kerb.server.preauth.pkinit;

import org.apache.kerberos.kerb.preauth.PluginRequestContext;
import org.apache.kerberos.kerb.spec.pa.PaDataType;
import org.apache.kerberos.kerb.spec.pa.pkinit.AuthPack;

public class PkinitRequestContext implements PluginRequestContext {

    public AuthPack authPack;
    public PaDataType paType;
}
