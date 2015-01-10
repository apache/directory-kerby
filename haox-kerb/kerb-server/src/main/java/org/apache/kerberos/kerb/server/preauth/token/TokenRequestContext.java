package org.apache.kerberos.kerb.server.preauth.token;

import org.apache.kerberos.kerb.preauth.PluginRequestContext;
import org.apache.kerberos.kerb.spec.pa.PaDataType;

public class TokenRequestContext implements PluginRequestContext {

    public boolean doIdentityMatching;
    public PaDataType paType;
    public boolean identityInitialized;
    public boolean identityPrompted;
    
}
