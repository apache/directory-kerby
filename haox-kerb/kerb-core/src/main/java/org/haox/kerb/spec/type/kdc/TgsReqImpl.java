package org.haox.kerb.spec.type.kdc;

import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.common.KrbMessageType;

public class TgsReqImpl extends KdcReqImpl implements AsReq {
    public TgsReqImpl() throws KrbException {
        super(KrbMessageType.TGS_REQ);
    }
}
