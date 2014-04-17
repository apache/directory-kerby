package org.haox.kerb.spec.type;

public class KrbOctetString implements KrbType {
    private byte[] value;

    public void setValue(byte[] value) {
        this.value = value;
    }

    public byte[] getValue() {
        return value;
    }
}
