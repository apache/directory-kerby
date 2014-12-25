package org.haox.kerb.spec.ticket;

import org.haox.kerb.spec.common.KrbFlags;

import static org.haox.kerb.spec.ticket.TicketFlag.INVALID;

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
