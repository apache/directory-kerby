package org.apache.kerberos.kerb.spec.ticket;

import org.apache.kerberos.kerb.spec.kdc.EncTgsRepPart;

public class ServiceTicket extends AbstractServiceTicket {
    public ServiceTicket(Ticket ticket, EncTgsRepPart encKdcRepPart) {
        super(ticket, encKdcRepPart);
    }
}
