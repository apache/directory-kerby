package org.apache.kerberos.kerb.server.preauth.pkinit;

import org.apache.kerberos.kerb.preauth.pkinit.IdentityOpts;
import org.apache.kerberos.kerb.preauth.pkinit.PluginOpts;

public class PkinitKdcContext {

    public PluginOpts pluginOpts;
    public IdentityOpts identityOpts;
    public String realm;
}
