package org.haox.kerb.spec.kdc;

import org.haox.kerb.spec.common.KrbMessageType;

/**
 TGS-REQ         ::= [APPLICATION 12] KDC-REQ
 */
public class TgsReq extends KdcReq {

    public TgsReq() {
        super(KrbMessageType.TGS_REQ);
    }
}
