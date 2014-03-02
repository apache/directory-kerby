package org.haox.kerb.spec.type.common;

import org.haox.kerb.spec.type.KrbType;

public class KrbTime implements KrbType {
    private long value;

    public long getValue() {
        return value;
    }

    public void setValue(long value) {
        this.value = value;
    }
}
