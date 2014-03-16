package org.haox.kerb.spec.type.ticket;

import org.haox.kerb.spec.type.common.KrbFlags;

public class TicketFlags extends KrbFlags {

    public TicketFlags() {
        this(0);
    }

    public TicketFlags(int value) {
        setFlags(value);
    }
}
