package org.haox.kerb.spec.type.kdc.impl;

import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.common.KrbMessageType;
import org.haox.kerb.spec.type.kdc.AsReq;

public class AsReqImpl extends KdcReqImpl implements AsReq {
    public AsReqImpl() throws KrbException {
        super(KrbMessageType.AS_REQ);
    }
}
