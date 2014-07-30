package org.haox.kerb.crypto2;

import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.common.EncryptionType;

public interface EncType {

    public EncryptionType eType();

    public int minimumPadSize();

    public int confounderSize();

    public int checksumType();

    public int checksumSize();

    public int blockSize();

    public int keySize();

    public byte[] encrypt(byte[] data, byte[] key, int usage)
        throws KrbException;

    public byte[] encrypt(byte[] data, byte[] key, byte[] ivec,
        int usage) throws KrbException;

    public byte[] decrypt(byte[] cipher, byte[] key, int usage)
        throws KrbException;

    public byte[] decrypt(byte[] cipher, byte[] key, byte[] ivec,
        int usage) throws KrbException;

    public byte[] decryptedData(byte[] data);
}
