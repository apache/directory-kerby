package org.apache.kerberos.kerb.spec.ticket;

import org.apache.kerberos.kerb.spec.common.EncryptionKey;
import org.apache.kerberos.kerb.spec.kdc.EncKdcRepPart;

public class AbstractServiceTicket {
    private Ticket ticket;
    private EncKdcRepPart encKdcRepPart;

    public AbstractServiceTicket(Ticket ticket, EncKdcRepPart encKdcRepPart) {
        this.ticket = ticket;
        this.encKdcRepPart = encKdcRepPart;
    }

    public Ticket getTicket() {
        return ticket;
    }

    public EncKdcRepPart getEncKdcRepPart() {
        return encKdcRepPart;
    }

    public EncryptionKey getSessionKey() {
        return encKdcRepPart.getKey();
    }

    public String getRealm() {
        return ticket.getRealm();
    }
}
