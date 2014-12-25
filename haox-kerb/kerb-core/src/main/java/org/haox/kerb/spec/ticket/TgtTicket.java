package org.haox.kerb.spec.ticket;

import org.haox.kerb.spec.common.PrincipalName;
import org.haox.kerb.spec.kdc.EncAsRepPart;

public class TgtTicket extends AbstractServiceTicket {
    private PrincipalName clientPrincipal;

    public TgtTicket(Ticket ticket, EncAsRepPart encKdcRepPart, String clientPrincipal) {
        super(ticket, encKdcRepPart);
        this.clientPrincipal = new PrincipalName(clientPrincipal);
    }

    public PrincipalName getClientPrincipal() {
        return clientPrincipal;
    }
}
