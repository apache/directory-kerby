package org.haox.kerb.spec.type.kdc;

import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.common.KrbMessageType;

/**
 TGS-REQ         ::= [APPLICATION 12] KDC-REQ
 */
public class TgsReq extends KdcReq {

    public TgsReq() throws KrbException {
        super(KrbMessageType.TGS_REQ);
    }
}
