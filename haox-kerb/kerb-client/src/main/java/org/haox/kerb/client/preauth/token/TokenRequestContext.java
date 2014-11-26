package org.haox.kerb.client.preauth.token;

import org.haox.kerb.client.preauth.PluginRequestContext;
import org.haox.kerb.spec.type.pa.PaDataType;

public class TokenRequestContext implements PluginRequestContext {

    public boolean doIdentityMatching;
    public PaDataType paType;
    public boolean identityInitialized;
    public boolean identityPrompted;
    
}
