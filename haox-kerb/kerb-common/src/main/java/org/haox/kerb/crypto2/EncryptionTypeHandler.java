package org.haox.kerb.crypto2;

import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.common.CheckSumType;
import org.haox.kerb.spec.type.common.EncryptionType;

public interface EncryptionTypeHandler extends CryptoTypeHandler {

    public EncryptionType eType();

    public int confounderSize();

    public int checksumSize();

    public int paddingSize();

    public int trailerSize();

    public byte[] str2key(String string,
                          String salt, byte[] param) throws KrbException;

    public int minimumPadSize();



    public CheckSumType checksumType();

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
