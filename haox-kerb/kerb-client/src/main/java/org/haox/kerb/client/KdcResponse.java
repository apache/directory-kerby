package org.haox.kerb.client;

import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.kdc.KdcRep;

public abstract class KdcResponse {
    private KrbContext context;
    private KdcRequest kdcRequest;
    private KdcRep kdcRep;

    public KdcResponse(KrbContext context, KdcRep kdcRep, KdcRequest request) {
        this.context = context;
        this.kdcRep = kdcRep;
        this.kdcRequest = request;
    }

    public KdcRep getKdcRep() {
        return kdcRep;
    }

    public KdcRequest getKdcRequest() {
        return kdcRequest;
    }

    public abstract void handle() throws KrbException;
}
