package org.haox.kerb.spec.type.ticket;

import org.haox.kerb.spec.type.common.KrbFlags;

import static org.haox.kerb.spec.type.ticket.TicketFlag.INVALID;

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

    public boolean isFlagSet(TicketFlag flag) {
        return isFlagSet(flag.getValue());
    }

    public void setFlag(TicketFlag flag)  {
        setFlag(flag.getValue());
    }

    public void clearFlag(TicketFlag flag) {
        clearFlag(flag.getValue());
    }
}
