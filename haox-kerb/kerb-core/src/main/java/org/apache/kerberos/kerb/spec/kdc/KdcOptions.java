package org.apache.kerberos.kerb.spec.kdc;

import org.apache.kerberos.kerb.spec.common.KrbFlags;

public class KdcOptions extends KrbFlags {

    public KdcOptions() {
        this(0);
    }

    public KdcOptions(int value) {
        setFlags(value);
    }
}
