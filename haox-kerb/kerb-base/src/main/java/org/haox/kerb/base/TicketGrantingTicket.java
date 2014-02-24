package org.haox.kerb.base;

public class TicketGrantingTicket extends ServiceTicket {
    private String clientPrincipal;

    public TicketGrantingTicket(Ticket ticket, EncKdcRepPart encKdcRepPart, String clientPrincipal) {
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
