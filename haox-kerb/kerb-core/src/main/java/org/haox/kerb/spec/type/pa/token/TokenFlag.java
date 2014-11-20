package org.haox.kerb.spec.type.pa.token;

import org.haox.kerb.spec.type.KrbEnum;

public enum TokenFlag implements KrbEnum {
    NONE(-1),
    ID_TOKEN_REQUIRED(0x40000000),
    AC_TOKEN_REQUIRED(0x20000000),
    BEARER_TOKEN_REQUIRED(0x10000000),
    HOK_TOKEN_REQUIRED(0x08000000);

    private final int value;

    private TokenFlag(int value) {
        this.value = value;
    }

    @Override
    public int getValue() {
        return value;
    }

    public static TokenFlag fromValue(int value) {
        for (KrbEnum e : values()) {
            if (e.getValue() == value) {
                return (TokenFlag) e;
            }
        }

        return NONE;
    }
}
