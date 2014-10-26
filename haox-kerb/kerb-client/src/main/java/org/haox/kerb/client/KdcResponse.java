package org.haox.kerb.client;

import org.haox.kerb.client.preauth.PreauthContext;
import org.haox.kerb.common.KrbProcessor;
import org.haox.kerb.spec.type.kdc.KdcRep;

/**
 * A wrapper for KdcRep response
 */
public abstract class KdcResponse implements KrbProcessor {
    private KdcRequest kdcRequest;
    private KdcRep kdcRep;

    public KdcResponse(KdcRep kdcRep) {
        this.kdcRep = kdcRep;
    }

    public KdcRep getKdcRep() {
        return kdcRep;
    }

    protected abstract PreauthContext getPreauthContext();

    public void setKdcRequest(KdcRequest request) {
        this.kdcRequest = request;
    }

    public KdcRequest getKdcRequest() {
        return kdcRequest;
    }
}
