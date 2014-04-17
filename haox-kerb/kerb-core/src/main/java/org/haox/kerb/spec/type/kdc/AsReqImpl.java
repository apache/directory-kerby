package org.haox.kerb.spec.type.kdc;

import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.common.KrbMessageType;

public class AsReqImpl extends KdcReqImpl implements AsReq {
    public AsReqImpl() throws KrbException {
        super(KrbMessageType.AS_REQ);
    }
}
