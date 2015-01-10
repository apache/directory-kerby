package org.apache.kerberos.kerb.spec.kdc;

import org.apache.kerberos.kerb.spec.common.KrbMessageType;

/**
 TGS-REP         ::= [APPLICATION 13] KDC-REP
 */
public class TgsRep extends KdcRep {
    public TgsRep() {
        super(KrbMessageType.TGS_REP);
    }
}
