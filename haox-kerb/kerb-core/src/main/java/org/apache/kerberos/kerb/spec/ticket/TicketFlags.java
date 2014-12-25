package org.apache.kerberos.kerb.spec.ticket;

import org.apache.kerberos.kerb.spec.common.KrbFlags;

import static org.apache.kerberos.kerb.spec.ticket.TicketFlag.INVALID;

public class TicketFlags extends KrbFlags {

    public TicketFlags() {
        this(0);
    }

    public TicketFlags(int value) {
        setFlags(value);
    }

    public boolean isInvalid() {
        return isFlagSet(INVALID.getValue());
    }
}
