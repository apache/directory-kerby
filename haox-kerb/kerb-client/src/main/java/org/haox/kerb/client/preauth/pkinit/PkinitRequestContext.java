package org.haox.kerb.client.preauth.pkinit;

import org.haox.kerb.client.preauth.PreauthRequestContext;
import org.haox.kerb.preauth.pkinit.IdentityOpts;
import org.haox.kerb.preauth.pkinit.PluginOpts;
import org.haox.kerb.spec.type.pa.PaDataType;

public class PkinitRequestContext implements PreauthRequestContext {

    public PkinitRequestOpts requestOpts = new PkinitRequestOpts();
    public IdentityOpts identityOpts = new IdentityOpts();
    public boolean doIdentityMatching;
    public PaDataType paType;
    public boolean rfc6112Kdc;
    public boolean identityInitialized;
    public boolean identityPrompted;
    
    public void updateRequestOpts(PluginOpts pluginOpts) {
        requestOpts.requireEku = pluginOpts.requireEku;
        requestOpts.acceptSecondaryEku = pluginOpts.acceptSecondaryEku;
        requestOpts.allowUpn = pluginOpts.allowUpn;
        requestOpts.usingRsa = pluginOpts.usingRsa;
        requestOpts.requireCrlChecking = pluginOpts.requireCrlChecking;
    }
}
