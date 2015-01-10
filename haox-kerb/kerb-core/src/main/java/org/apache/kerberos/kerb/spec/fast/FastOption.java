package org.apache.kerberos.kerb.spec.fast;

import org.apache.kerberos.kerb.spec.KrbEnum;

public enum FastOption implements KrbEnum {
    NONE(-1),
    RESERVED(0),
    HIDE_CLIENT_NAMES(1),

    KDC_FOLLOW_REFERRALS(16);

    private final int value;

    private FastOption(int value) {
        this.value = value;
    }

    @Override
    public int getValue() {
        return value;
    }

    public static FastOption fromValue(int value) {
        for (KrbEnum e : values()) {
            if (e.getValue() == value) {
                return (FastOption) e;
            }
        }

        return NONE;
    }
}
