package org.apache.kerberos.kerb.spec.kdc;

import org.apache.kerberos.kerb.spec.common.KrbMessageType;

/**
 AS-REQ          ::= [APPLICATION 10] KDC-REQ
 */
public class AsReq extends KdcReq {
    public AsReq() {
        super(KrbMessageType.AS_REQ);
    }
}
