package org.haox.kerb.client.preauth.pkinit;

import org.haox.kerb.client.preauth.PreauthRequestContext;
import org.haox.kerb.preauth.pkinit.IdentityOpts;
import org.haox.kerb.spec.type.pa.PaDataType;

public class PkinitRequestContext implements PreauthRequestContext {

    public PkinitRequestOpts requestOpts;
    public IdentityOpts identityOpts;
    public boolean doIdentityMatching;
    public PaDataType paType;
    public boolean rfc6112Kdc;
    public boolean identityInitialized;
    public boolean identityPrompted;
}
