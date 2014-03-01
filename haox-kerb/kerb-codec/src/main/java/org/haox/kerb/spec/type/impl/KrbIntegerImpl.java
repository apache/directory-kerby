package org.haox.kerb.spec.type.impl;

import org.haox.kerb.codec.AbstractKrbType;
import org.haox.kerb.spec.type.KrbInteger;
import org.haox.kerb.spec.type.KrbOctetString;

import java.math.BigInteger;

public class KrbIntegerImpl extends AbstractKrbType implements KrbInteger {
    private BigInteger value;

    @Override
    public void setValue(BigInteger value) {
        this.value = value;
    }

    @Override
    public BigInteger getValue() {
        return value;
    }
}
