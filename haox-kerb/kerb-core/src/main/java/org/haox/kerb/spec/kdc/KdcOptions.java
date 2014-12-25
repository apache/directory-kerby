package org.haox.kerb.spec.kdc;

import org.haox.kerb.spec.common.KrbFlags;

public class KdcOptions extends KrbFlags {

    public KdcOptions() {
        this(0);
    }

    public KdcOptions(int value) {
        setFlags(value);
    }
}
