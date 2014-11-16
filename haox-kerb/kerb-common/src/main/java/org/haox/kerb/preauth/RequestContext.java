package org.haox.kerb.preauth;

import org.haox.kerb.spec.type.pa.PaDataType;

public class RequestContext {

    protected RequestOpts requestOpts;
    protected IdentityOpts identityOpts;
    protected boolean doIdentityMatching;
    protected PaDataType paType;
    protected boolean rfc6112Kdc;
    protected boolean identityInitialized;
    protected boolean identityPrompted;
}
