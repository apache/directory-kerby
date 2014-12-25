package org.apache.kerberos.kerb.spec.common;

import org.apache.kerberos.kerb.spec.KrbEnum;

public enum TokenFormat implements KrbEnum {
    NONE                (0),
    JWT                 (1);

    private final int value;

    private TokenFormat(int value) {
        this.value = value;
    }

    @Override
    public int getValue() {
        return value;
    }

    public static TokenFormat fromValue(Integer value) {
        if (value != null) {
            for (KrbEnum e : values()) {
                if (e.getValue() == value.intValue()) {
                    return (TokenFormat) e;
                }
            }
        }

        return NONE;
    }
}
