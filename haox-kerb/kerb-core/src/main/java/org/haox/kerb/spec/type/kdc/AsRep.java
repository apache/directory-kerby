package org.haox.kerb.spec.type.kdc;

import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.common.KrbMessageType;

/**
 AS-REP          ::= [APPLICATION 11] KDC-REP
 */
public class AsRep extends KdcRep {

    public AsRep() throws KrbException {
        super(KrbMessageType.AS_REP);
    }
}
