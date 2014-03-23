package org.haox.kerb.spec.type.kdc.impl;

import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.common.KrbMessageType;
import org.haox.kerb.spec.type.kdc.AsReq;

public class TgsReqImpl extends KdcReqImpl implements AsReq {
    public TgsReqImpl() throws KrbException {
        super(KrbMessageType.TGS_REQ);
    }
}
