package org.apache.kerberos.kerb.spec.ap;

import org.apache.kerberos.kerb.spec.common.KrbFlags;

public class ApOptions extends KrbFlags {

    public ApOptions() {
        this(0);
    }

    public ApOptions(int value) {
        setFlags(value);
    }
}
