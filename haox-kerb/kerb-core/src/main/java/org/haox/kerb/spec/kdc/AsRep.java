package org.haox.kerb.spec.kdc;

import org.haox.kerb.spec.common.KrbMessageType;

/**
 AS-REP          ::= [APPLICATION 11] KDC-REP
 */
public class AsRep extends KdcRep {

    public AsRep() {
        super(KrbMessageType.AS_REP);
    }
}
