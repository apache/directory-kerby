package org.haox.kerb.spec.type.ticket;

import org.haox.kerb.spec.type.kdc.EncTgsRepPart;

public class ServiceTicket extends AbstractServiceTicket {
    public ServiceTicket(Ticket ticket, EncTgsRepPart encKdcRepPart) {
        super(ticket, encKdcRepPart);
    }
}
