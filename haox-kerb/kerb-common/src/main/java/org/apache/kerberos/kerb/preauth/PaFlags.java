package org.apache.kerberos.kerb.preauth;

import org.apache.kerberos.kerb.spec.common.KrbFlags;

public class PaFlags extends KrbFlags {

    public PaFlags() {
        this(0);
    }

    public PaFlags(int value) {
        setFlags(value);
    }

    public boolean isReal() {
        return isFlagSet(PaFlag.PA_REAL);
    }
}
