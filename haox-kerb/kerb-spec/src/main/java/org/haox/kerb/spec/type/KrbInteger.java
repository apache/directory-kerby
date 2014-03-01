package org.haox.kerb.spec.type;

import java.math.BigInteger;

public interface KrbInteger extends KrbType {
    public void setValue(BigInteger value);
    public BigInteger getValue();
}
