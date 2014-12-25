package org.haox.kerb.spec.fast;

import org.haox.kerb.spec.common.KrbFlags;

public class FastOptions extends KrbFlags {

    public FastOptions() {
        this(0);
    }

    public FastOptions(int value) {
        setFlags(value);
    }
}
