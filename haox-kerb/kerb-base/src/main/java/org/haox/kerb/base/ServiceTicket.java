package org.haox.kerb.base;

public class ServiceTicket {
    protected Ticket ticket;
    protected EncKdcRepPart encKdcRepPart;

    public ServiceTicket(Ticket ticket, EncKdcRepPart encKdcRepPart) {
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
