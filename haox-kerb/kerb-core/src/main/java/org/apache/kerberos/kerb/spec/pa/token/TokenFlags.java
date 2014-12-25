package org.apache.kerberos.kerb.spec.pa.token;

import org.apache.kerberos.kerb.spec.common.KrbFlags;

import static org.apache.kerberos.kerb.spec.ticket.TicketFlag.INVALID;

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
