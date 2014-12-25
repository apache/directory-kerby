package org.haox.kerb.server.preauth.token;

import org.haox.kerb.preauth.PluginRequestContext;
import org.haox.kerb.spec.pa.PaDataType;

public class TokenRequestContext implements PluginRequestContext {

    public boolean doIdentityMatching;
    public PaDataType paType;
    public boolean identityInitialized;
    public boolean identityPrompted;
    
}
