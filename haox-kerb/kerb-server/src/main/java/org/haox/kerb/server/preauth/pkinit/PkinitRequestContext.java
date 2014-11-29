package org.haox.kerb.server.preauth.pkinit;

import org.haox.kerb.preauth.PluginRequestContext;
import org.haox.kerb.spec.type.pa.PaDataType;
import org.haox.kerb.spec.type.pa.pkinit.AuthPack;

public class PkinitRequestContext implements PluginRequestContext {

    public AuthPack authPack;
    public PaDataType paType;
}
