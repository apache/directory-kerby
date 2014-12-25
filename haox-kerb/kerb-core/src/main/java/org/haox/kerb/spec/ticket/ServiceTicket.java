package org.haox.kerb.spec.ticket;

import org.haox.kerb.spec.kdc.EncTgsRepPart;

public class ServiceTicket extends AbstractServiceTicket {
    public ServiceTicket(Ticket ticket, EncTgsRepPart encKdcRepPart) {
        super(ticket, encKdcRepPart);
    }
}
