package org.apache.kerberos.kerb.spec.fast;

import org.apache.kerberos.kerb.spec.common.KrbFlags;

public class FastOptions extends KrbFlags {

    public FastOptions() {
        this(0);
    }

    public FastOptions(int value) {
        setFlags(value);
    }
}
