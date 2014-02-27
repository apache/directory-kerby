package org.haox.kerb.spec.type.kdc;

import org.haox.kerb.spec.type.common.KrbMessageType;

public class TgsReq extends KdcReq {
    public TgsReq() {
        super(KrbMessageType.TGS_REQ);
    }
}
