package org.haox.kerb.spec.type.ticket;

import org.haox.kerb.spec.type.kdc.EncKdcRepPart;

public class AbstractServiceTicket {
    protected Ticket ticket;
    protected EncKdcRepPart encKdcRepPart;

    public AbstractServiceTicket(Ticket ticket, EncKdcRepPart encKdcRepPart) {
        this.ticket = ticket;
        this.encKdcRepPart = encKdcRepPart;
    }

    public Ticket getTicket() {
        return ticket;
    }

    public void setTicket(Ticket ticket) {
        this.ticket = ticket;
    }

    public EncKdcRepPart getEncKdcRepPart() {
        return encKdcRepPart;
    }

    public void setEncKdcRepPart(EncKdcRepPart encKdcRepPart) {
        this.encKdcRepPart = encKdcRepPart;
    }
}
