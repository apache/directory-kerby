package org.haox.kerb.spec.type.common;

import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.KrbEnum;
import org.haox.kerb.spec.type.KrbFactory;
import org.haox.kerb.spec.type.KrbInteger;

import java.math.BigInteger;

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

    public KrbInteger asInteger() throws KrbException {
        KrbInteger tmp = KrbFactory.create(KrbInteger.class);
        tmp.setValue(BigInteger.valueOf(value));
        return tmp;
    }
    public static KrbMessageType fromValue(KrbInteger value) {
        if (value != null) {
            for (KrbEnum e : values()) {
                if (e.getValue() == value.getValue().intValue()) {
                    return (KrbMessageType) e;
                }
            }
        }

        return NONE;
    }
}
