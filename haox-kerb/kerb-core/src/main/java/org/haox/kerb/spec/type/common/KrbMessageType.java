package org.haox.kerb.spec.type.common;

import org.haox.kerb.spec.type.KrbEnum;

public enum KrbMessageType implements KrbEnum {
    NONE(-1),
    AS_REQ(10),
    AS_REP(11),
    TGS_REQ(12),
    TGS_REP(13),
    AP_REQ(14),
    AP_REP(15),
    KRB_SAFE(20),
    KRB_PRIV(21),
    KRB_CRED(22),
    KRB_ERROR(30);

    private int value;

    private KrbMessageType(int value) {
        this.value = value;
    }

    @Override
    public int getValue() {
        return value;
    }

    public static KrbMessageType fromValue(Integer value) {
        if (value != null) {
            for (KrbEnum e : values()) {
                if (e.getValue() == value.intValue()) {
                    return (KrbMessageType) e;
                }
            }
        }

        return NONE;
    }
}
