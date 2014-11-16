package org.haox.kerb.preauth;

public class PluginOpts {

    // From MIT Krb5 _pkinit_plg_opts

    // require EKU checking (default is true)
    protected boolean requireEku = true;
    // accept secondary EKU (default is false)
    protected boolean acceptSecondaryEku = false;
    // allow UPN-SAN instead of pkinit-SAN
    protected boolean allowUpn = true;
    // selects DH or RSA based pkinit
    protected boolean usingRsa = true;
    // require CRL for a CA (default is false)
    protected boolean requireCrlChecking = false;
    // minimum DH modulus size allowed
    protected int dhMinBits;
}
