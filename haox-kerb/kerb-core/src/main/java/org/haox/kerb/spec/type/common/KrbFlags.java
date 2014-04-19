package org.haox.kerb.spec.type.common;

import org.haox.asn1.type.Asn1Integer;
import org.haox.kerb.spec.type.KrbEnum;

/**
 KrbFlags   ::= BIT STRING (SIZE (32..MAX))
 -- minimum number of bits shall be sent,
 -- but no fewer than 32
 */
public class KrbFlags extends Asn1Integer {
    public void setFlags(int value) {
        setValue(value);
    }

    public boolean isFlagSet(int flag) {
        return (getValue() & flag) != 0;
    }

    public void setFlag(int flag)  {
        setValue(getValue() | flag);
    }

    public void clearFlag(int flag) {
        setValue(getValue() & ~flag);
    }

    public void clear() {
        setValue(0);
    }

    public boolean isFlagSet(KrbEnum flag) {
        return isFlagSet(flag.getValue());
    }

    public void setFlag(KrbEnum flag)  {
        setFlag(flag.getValue());
    }

    public void clearFlag(KrbEnum flag) {
        clearFlag(flag.getValue());
    }
}
