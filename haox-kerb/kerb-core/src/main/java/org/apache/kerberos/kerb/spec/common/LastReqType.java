package org.apache.kerberos.kerb.spec.common;

import org.apache.kerberos.kerb.spec.KrbEnum;

public enum LastReqType implements KrbEnum {
    NONE(0),
    ALL_LAST_TGT(1),
    THE_LAST_TGT(-1),
    ALL_LAST_INITIAL(2),
    THE_LAST_INITIAL(-2),
    ALL_LAST_TGT_ISSUED(3),
    THE_LAST_TGT_ISSUED(-3),
    ALL_LAST_RENEWAL(4),
    THE_LAST_RENEWAL(-4),
    ALL_LAST_REQ(5),
    THE_LAST_REQ(-5),
    ALL_PW_EXPTIME(6),
    THE_PW_EXPTIME(-6),
    ALL_ACCT_EXPTIME(7),
    THE_ACCT_EXPTIME(-7);

    private int value;

    private LastReqType(int value) {
        this.value = value;
    }

    @Override
    public int getValue() {
        return value;
    }

    public static LastReqType fromValue(Integer value) {
        if (value != null) {
            for (KrbEnum e : values()) {
                if (e.getValue() == value) {
                    return (LastReqType) e;
                }
            }
        }
        return NONE;
    }
}
