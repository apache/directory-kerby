package org.haox.kerb.client;

import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.kdc.AsRep;
import org.haox.kerb.spec.type.kdc.EncAsRepPart;
import org.haox.kerb.spec.type.ticket.TgtTicket;

public class AsResponse extends KdcResponse {

    public AsResponse(KrbContext context, AsRep asRep) {
        super(context, asRep);
    }

    public AsRep getAsRep() {
        return (AsRep) getKdcRep();
    }

    @Override
    public void handle() throws KrbException {
        super.handle();
    }

    public TgtTicket getTicket() {
        TgtTicket TgtTicket = new TgtTicket(getAsRep().getTicket(),
                (EncAsRepPart) getAsRep().getEncPart(), getAsRep().getCname().getName());
        return TgtTicket;
    }
}
