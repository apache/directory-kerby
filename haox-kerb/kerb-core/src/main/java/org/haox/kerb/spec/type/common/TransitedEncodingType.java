package org.haox.kerb.spec.type.common;

import org.haox.kerb.spec.type.KrbEnum;

public enum TransitedEncodingType implements KrbEnum {
    UNKNOWN(-1),
    NULL(0),
    DOMAIN_X500_COMPRESS(1);

    private final int value;

    private TransitedEncodingType(int value) {
        this.value = value;
    }

    @Override
    public int getValue() {
        return value;
    }

    public static TransitedEncodingType fromValue(Integer value) {
        if (value != null) {
            for (KrbEnum e : values()) {
                if (e.getValue() == value.intValue()) {
                    return (TransitedEncodingType) e;
                }
            }
        }

        return NULL;
    }
}
