package org.haox.kerb.spec.type.common;

import org.haox.kerb.spec.type.KrbType;

/**
 KrbFlags   ::= BIT STRING (SIZE (32..MAX))
 -- minimum number of bits shall be sent,
 -- but no fewer than 32
 */
public class KrbFlags implements KrbType {
    private int value = 0;

    public void setFlags(int value) {
        this.value = value;
    }

    public boolean isFlagSet(int flag) {
        return (value & flag) != 0;
    }

    public void setFlag(int flag)  {
        value |= flag;
    }

    public void clearFlag(int flag) {
        value &= ~flag;
    }

    public void clear() {
        value = 0;
    }
}
