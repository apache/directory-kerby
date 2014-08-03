package org.haox.kerb.crypto2.enc;

import org.haox.kerb.crypto2.Crc32;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.common.CheckSumType;
import org.haox.kerb.spec.type.common.EncryptionType;

public class DesCbcCrcEnc extends DesCbcEnc {

    public DesCbcCrcEnc() {
    }

    public EncryptionType eType() {
        return EncryptionType.DES_CBC_CRC;
    }

    public int minimumPadSize() {
        return 4;
    }

    public int confounderSize() {
        return 8;
    }

    public CheckSumType checksumType() {
        return CheckSumType.CRC32;
    }

    public int checksumSize() {
        return 4;
    }

    /**
     * Encrypts data using DES in CBC mode with CRC32.
     * @param data the data to be encrypted.
     * @param key  the secret key to encrypt the data. It is also used as initialization vector during cipher block chaining.
     * @return the buffer for cipher text.
     *
     * @written by Yanni Zhang, Dec 10, 1999
     */
    public byte[] encrypt(byte[] data, byte[] key, int usage)
         throws KrbException {
        return encrypt(data, key, key, usage);
    }

    /**
     * Decrypts data with provided key using DES in CBC mode with CRC32.
     * @param cipher the cipher text to be decrypted.
     * @param key  the secret key to decrypt the data.
     *
     * @written by Yanni Zhang, Dec 10, 1999
     */
    public byte[] decrypt(byte[] cipher, byte[] key, int usage)
         throws KrbException{
        return decrypt(cipher, key, key, usage);
    }

    protected byte[] calculateChecksum(byte[] data, int size) {
        return Crc32.byte2crc32sum_bytes(data, size);
    }

}
