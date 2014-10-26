package org.haox.kerb.common.preauth;

import org.haox.kerb.spec.type.common.KrbFlags;

public class PaFlags extends KrbFlags {

    public PaFlags() {
        this(0);
    }

    public PaFlags(int value) {
        setFlags(value);
    }
}
