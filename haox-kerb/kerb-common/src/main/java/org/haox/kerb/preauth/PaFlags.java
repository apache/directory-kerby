package org.haox.kerb.preauth;

import org.haox.kerb.spec.type.common.KrbFlags;

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
