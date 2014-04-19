package org.haox.kerb.spec.type.kdc;

import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.common.KrbMessageType;

/**
 AS-REQ          ::= [APPLICATION 10] KDC-REQ
 */
public class AsReq extends KdcReq {
    public AsReq() throws KrbException {
        super(KrbMessageType.AS_REQ);
    }
}
