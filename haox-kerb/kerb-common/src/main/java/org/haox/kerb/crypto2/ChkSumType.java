package org.haox.kerb.crypto2;

import org.haox.kerb.spec.KrbException;

public interface ChkSumType {

    public abstract int confounderSize();

    public abstract int cksumType();

    public abstract boolean isSafe();

    public abstract int cksumSize();

    public abstract int keySize();

    public abstract byte[] calculateChecksum(byte[] data, int size)
        throws KrbException;

    public abstract byte[] calculateKeyedChecksum(byte[] data, int size,
        byte[] key, int usage) throws KrbException;

    public abstract boolean verifyKeyedChecksum(byte[] data, int size,
        byte[] key, byte[] checksum, int usage) throws KrbException;
}
