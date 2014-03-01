package org.haox.kerb.spec.type;

public interface KrbOctetString extends KrbType {
    public void setValue(byte[] value);
    public byte[] getValue();
}
