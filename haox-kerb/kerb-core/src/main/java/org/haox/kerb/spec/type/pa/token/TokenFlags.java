package org.haox.kerb.spec.type.pa.token;

import org.haox.kerb.spec.type.common.KrbFlags;

import static org.haox.kerb.spec.type.ticket.TicketFlag.INVALID;

public class TokenFlags extends KrbFlags {

    public TokenFlags() {
        this(0);
    }

    public TokenFlags(int value) {
        setFlags(value);
    }

    public boolean isInvalid() {
        return isFlagSet(INVALID.getValue());
    }
}
