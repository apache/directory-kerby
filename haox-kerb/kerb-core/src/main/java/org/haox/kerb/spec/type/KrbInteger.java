package org.haox.kerb.spec.type;

import java.math.BigInteger;

public class KrbInteger implements KrbType {
    private BigInteger value;

    public void setValue(BigInteger value) {
        this.value = value;
    }

    public BigInteger getValue() {
        return value;
    }
}
