package org.haox.kerb.spec.type.ap;

import org.haox.kerb.spec.type.common.KrbFlags;

public class ApOptions extends KrbFlags {

    public ApOptions() {
        setFlags(0);
    }

    public ApOptions(int value) {
        setFlags(value);
    }
}
