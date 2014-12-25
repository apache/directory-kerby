package org.haox.kerb.spec.ap;

import org.haox.kerb.spec.KrbEnum;

/**
 APOptions       ::= KrbFlags
 -- reserved(0),
 -- use-session-key(1),
 -- mutual-required(2)
 */
public enum ApOption implements KrbEnum {
    NONE(-1),
    RESERVED(0x80000000),
    USE_SESSION_KEY(0x40000000),
    MUTUAL_REQUIRED(0x20000000),
    ETYPE_NEGOTIATION(0x00000002),
    USE_SUBKEY(0x00000001);

    private final int value;

    private ApOption(int value) {
        this.value = value;
    }

    @Override
    public int getValue() {
        return value;
    }

    public static ApOption fromValue(int value) {
        for (KrbEnum e : values()) {
            if (e.getValue() == value) {
                return (ApOption) e;
            }
        }

        return NONE;
    }
}