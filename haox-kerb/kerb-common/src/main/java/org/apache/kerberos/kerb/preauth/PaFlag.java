package org.apache.kerberos.kerb.preauth;

import org.apache.kerberos.kerb.spec.KrbEnum;

public enum PaFlag implements KrbEnum {
    NONE(-1),
    PA_REAL(0x01),
    PA_INFO(0x02);

    private final int value;

    private PaFlag(int value) {
        this.value = value;
    }

    @Override
    public int getValue() {
        return value;
    }

    public static PaFlag fromValue(int value) {
        for (KrbEnum e : values()) {
            if (e.getValue() == value) {
                return (PaFlag) e;
            }
        }

        return NONE;
    }
}
