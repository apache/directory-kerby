package org.haox.kerb.spec.ap;

import org.haox.kerb.spec.common.KrbFlags;

public class ApOptions extends KrbFlags {

    public ApOptions() {
        this(0);
    }

    public ApOptions(int value) {
        setFlags(value);
    }
}
