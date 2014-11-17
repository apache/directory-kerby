package org.haox.kerb.preauth.pkinit;

import java.util.List;

public class IdentityOpts {

    // From MIT Krb5 _pkinit_identity_opts
    public String identity;
    public List<String> AltIdentities;
    public List<String> anchors;
    public List<String> intermediates;
    public List<String> crls;
    public String ocsp;
    public int  idtype;
    public String certFile;
    public String keyFile;

    // PKCS11
    public String p11ModuleName;
    public int slotid;
    public String tokenLabel;
    public String certId;
    public String certLabel;
}
