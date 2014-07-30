package org.haox.kerb.crypto2;

import org.haox.kerb.common.Checksum;
import org.haox.kerb.common.EncryptedData;
import org.haox.kerb.spec.KrbException;

public class NullEType extends EType {

    public NullEType() {
    }

    public int eType() {
        return EncryptedData.ETYPE_NULL;
    }

    public int minimumPadSize() {
        return 0;
    }

    public int confounderSize() {
        return 0;
    }

    public int checksumType() {
        return Checksum.CKSUMTYPE_NULL;
    }

    public int checksumSize() {
        return 0;
    }

    public int blockSize() {
        return 1;
    }

    public int keySize() {
        return 0;
    }

    public byte[] encrypt(byte[] data, byte[] key, int usage) {
        byte[] cipher = new byte[data.length];
        System.arraycopy(data, 0, cipher, 0, data.length);
        return cipher;
    }

    public byte[] encrypt(byte[] data, byte[] key, byte[] ivec, int usage) {
        byte[] cipher = new byte[data.length];
        System.arraycopy(data, 0, cipher, 0, data.length);
        return cipher;
    }

    public byte[] decrypt(byte[] cipher, byte[] key, int usage)
        throws KrbException {
            return cipher.clone();
    }

    public byte[] decrypt(byte[] cipher, byte[] key, byte[] ivec, int usage)
        throws KrbException {
            return cipher.clone();
    }
}
