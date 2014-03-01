package org.haox.kerb.spec.type.impl;

import org.haox.kerb.codec.AbstractKrbType;
import org.haox.kerb.spec.type.KrbOctetString;

public class KrbOctetStringImpl extends AbstractKrbType implements KrbOctetString {
    private byte[] value;

    @Override
    public void setValue(byte[] value) {
        this.value = value;
    }

    @Override
    public byte[] getValue() {
        return value;
    }
}
