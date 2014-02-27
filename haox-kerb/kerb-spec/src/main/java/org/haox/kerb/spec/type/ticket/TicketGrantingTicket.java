package org.haox.kerb.spec.type.ticket;

import org.haox.kerb.spec.type.kdc.EncAsRepPart;

public class TicketGrantingTicket extends AbstractServiceTicket {
    private String clientPrincipal;

    public TicketGrantingTicket(Ticket ticket, EncAsRepPart encKdcRepPart, String clientPrincipal) {
        super(ticket, encKdcRepPart);
        this.clientPrincipal = clientPrincipal;
    }

    public String getClientPrincipal() {
        return clientPrincipal;
    }

    public void setClientPrincipal(String clientPrincipal) {
        this.clientPrincipal = clientPrincipal;
    }
}
