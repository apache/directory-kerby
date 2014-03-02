package org.haox.kerb.spec.type.common;

import org.haox.kerb.spec.type.KrbEnum;
import org.haox.kerb.spec.type.KrbInteger;

public enum NameType implements KrbEnum {
    NT_UNKNOWN(0),
    NT_PRINCIPAL(1),
    NT_SRV_INST(2),
    NT_SRV_HST(3),
    NT_SRV_XHST(4),
    NT_UID(5);
    
    private int value;

    private NameType(int value) {
        this.value = value;
    }

    @Override
    public int getValue() {
        return value;
    }

    public static NameType fromValue(KrbInteger value) {
        if (value != null) {
            for (KrbEnum e : values()) {
                if (e.getValue() == value.getValue().intValue()) {
                    return (NameType) e;
                }
            }
        }

        return NT_UNKNOWN;
    }
}
