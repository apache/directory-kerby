package org.haox.kerb.spec.type.ticket;

import org.haox.kerb.spec.type.kdc.EncAsRepPart;

public class TgtTicket extends AbstractServiceTicket {
    private String clientPrincipal;

    public TgtTicket(Ticket ticket, EncAsRepPart encKdcRepPart, String clientPrincipal) {
        super(ticket, encKdcRepPart);
        this.clientPrincipal = clientPrincipal;
    }

    public String getClientPrincipal() {
        return clientPrincipal;
    }
}
