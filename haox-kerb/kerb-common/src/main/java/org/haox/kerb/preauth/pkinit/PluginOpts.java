package org.haox.kerb.preauth.pkinit;

public class PluginOpts {

    // From MIT Krb5 _pkinit_plg_opts

    // require EKU checking (default is true)
    public boolean requireEku = true;
    // accept secondary EKU (default is false)
    public boolean acceptSecondaryEku = false;
    // allow UPN-SAN instead of pkinit-SAN
    public boolean allowUpn = true;
    // selects DH or RSA based pkinit
    public boolean usingRsa = true;
    // require CRL for a CA (default is false)
    public boolean requireCrlChecking = false;
    // the size of the Diffie-Hellman key the client will attempt to use.
    // The acceptable values are 1024, 2048, and 4096. The default is 2048.
    public int dhMinBits = 2048;
}
