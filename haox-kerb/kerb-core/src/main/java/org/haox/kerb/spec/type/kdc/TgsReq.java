package org.haox.kerb.spec.type.kdc;

import org.haox.kerb.spec.type.common.KrbMessageType;

/**
 TGS-REQ         ::= [APPLICATION 12] KDC-REQ
 */
public class TgsReq extends KdcReq {

    public TgsReq() {
        super(KrbMessageType.TGS_REQ);
    }
}
