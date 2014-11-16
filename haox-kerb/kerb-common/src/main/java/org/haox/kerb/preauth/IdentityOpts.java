package org.haox.kerb.preauth;

import java.util.List;

public class IdentityOpts {

    // From MIT Krb5 _pkinit_identity_opts
    protected String identity;
    protected List<String> AltIdentities;
    protected List<String> anchors;
    protected List<String> intermediates;
    protected List<String> crls;
    protected String ocsp;
    protected int  idtype;
    protected String certFile;
    protected String keyFile;

    // PKCS11
    protected String p11ModuleName;
    protected int slotid;
    protected String tokenLabel;
    protected String certId;
    protected String certLabel;
}
