package org.haox.kerb.base;

public class EncryptionKey {
    private EncryptionType keyType;
    private byte[] keyData;

    public EncryptionType getKeyType() {
        return keyType;
    }

    public void setKeyType(EncryptionType keyType) {
        this.keyType = keyType;
    }

    public byte[] getKeyData() {
        return keyData;
    }

    public void setKeyData(byte[] keyData) {
        this.keyData = keyData;
    }
}
