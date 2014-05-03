package org.haox.kerb.spec.type.common;

import org.haox.asn1.type.Asn1BitString;
import org.haox.asn1.type.Asn1Integer;
import org.haox.kerb.spec.type.KrbEnum;

/**
 KrbFlags   ::= BIT STRING (SIZE (32..MAX))
 -- minimum number of bits shall be sent,
 -- but no fewer than 32
 */
public class KrbFlags extends Asn1BitString {
    private int flags;

    public KrbFlags() {
        this(0);
    }

    public KrbFlags(int value) {
        super();
        setFlags(value);
    }

    public void setFlags(int flags) {
        this.flags = flags;
    }

    public boolean isFlagSet(int flag) {
        return (flags & flag) != 0;
    }

    public void setFlag(int flag)  {
        flags |= flag;
    }

    public void clearFlag(int flag) {
        flags &= ~flag;
    }

    public void clear() {
        flags = 0;
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
