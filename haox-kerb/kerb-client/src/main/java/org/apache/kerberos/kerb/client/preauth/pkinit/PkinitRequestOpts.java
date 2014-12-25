package org.apache.kerberos.kerb.client.preauth.pkinit;

public class PkinitRequestOpts {

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
    // initial request DH modulus size (default=1024)
    public int dhSize = 1024;

    public boolean requireHostnameMatch = true;
}
