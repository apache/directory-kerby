package org.haox.kerb.client.preauth.token;

import org.haox.kerb.client.preauth.PreauthRequestContext;
import org.haox.kerb.client.preauth.pkinit.PkinitRequestOpts;
import org.haox.kerb.preauth.pkinit.IdentityOpts;
import org.haox.kerb.preauth.pkinit.PluginOpts;
import org.haox.kerb.spec.type.pa.PaDataType;

public class TokenRequestContext implements PreauthRequestContext {

    public boolean doIdentityMatching;
    public PaDataType paType;
    public boolean identityInitialized;
    public boolean identityPrompted;
    
}
