package org.haox.kerb.spec.type.kdc;

import org.haox.kerb.spec.type.common.KrbMessageType;

/**
 TGS-REP         ::= [APPLICATION 13] KDC-REP
 */
public class TgsRep extends KdcRep {
    public TgsRep() {
        super(KrbMessageType.TGS_REP);
    }
}
