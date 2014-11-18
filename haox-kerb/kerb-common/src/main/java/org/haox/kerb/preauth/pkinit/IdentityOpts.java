package org.haox.kerb.preauth.pkinit;

import java.util.ArrayList;
import java.util.List;

public class IdentityOpts {

    // From MIT Krb5 _pkinit_identity_opts
    public String identity;
    public List<String> AltIdentities = new ArrayList<String>(1);
    public List<String> anchors = new ArrayList<String>(4);
    public List<String> intermediates = new ArrayList<String>(2);
    public List<String> crls = new ArrayList<String>(2);
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
