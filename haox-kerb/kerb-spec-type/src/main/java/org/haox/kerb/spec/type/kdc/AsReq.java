package org.haox.kerb.spec.type.kdc;

import org.haox.kerb.spec.type.common.KrbMessageType;

public class AsReq extends KdcReq {
    public AsReq() {
        super(KrbMessageType.AS_REQ);
    }
}
