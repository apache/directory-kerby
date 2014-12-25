package org.apache.kerberos.kerb.client.preauth.pkinit;

import org.apache.kerberos.kerb.preauth.PluginRequestContext;
import org.apache.kerberos.kerb.preauth.pkinit.IdentityOpts;
import org.apache.kerberos.kerb.preauth.pkinit.PluginOpts;
import org.apache.kerberos.kerb.spec.pa.PaDataType;

public class PkinitRequestContext implements PluginRequestContext {

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
