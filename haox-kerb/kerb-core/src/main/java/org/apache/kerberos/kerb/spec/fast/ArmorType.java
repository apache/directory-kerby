package org.apache.kerberos.kerb.spec.fast;

import org.apache.kerberos.kerb.spec.KrbEnum;

public enum ArmorType implements KrbEnum {
    NONE                (0),
    ARMOR_AP_REQUEST              (1);

    private final int value;

    private ArmorType(int value) {
        this.value = value;
    }

    @Override
    public int getValue() {
        return value;
    }

    public static ArmorType fromValue(Integer value) {
        if (value != null) {
            for (KrbEnum e : values()) {
                if (e.getValue() == value.intValue()) {
                    return (ArmorType) e;
                }
            }
        }

        return NONE;
    }
}
