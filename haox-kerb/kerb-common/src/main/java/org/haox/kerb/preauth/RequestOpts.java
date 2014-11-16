package org.haox.kerb.preauth;

public class RequestOpts {

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
    // initial request DH modulus size (default=1024)
    protected int dhSize = 1024;

    protected boolean requireHostnameMatch = true;
}
