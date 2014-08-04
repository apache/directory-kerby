package org.haox.kerb.crypto2.enc;

import org.haox.kerb.crypto2.Des3;
import org.haox.kerb.crypto2.key.Des3KeyMaker;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.common.CheckSumType;
import org.haox.kerb.spec.type.common.EncryptionType;

import java.security.GeneralSecurityException;

public final class Des3CbcHmacSha1KdEnc extends AbstractEncryptionTypeHandler {

    public Des3CbcHmacSha1KdEnc() {
        super(null, null, new Des3KeyMaker());
    }

    public EncryptionType eType() {
        return EncryptionType.DES3_CBC_SHA1_KD;
    }

    public int minimumPadSize() {
        return 0;
    }

    public int confounderSize() {
        return blockSize();
    }

    public CheckSumType checksumType() {
        return CheckSumType.HMAC_SHA1_DES3_KD;
    }

    public int checksumSize() {
        return Des3.getChecksumLength();
    }

    public int blockSize() {
        return 8;
    }

    public int keySize() {
        return 24; // bytes
    }

    public byte[] encrypt(byte[] data, byte[] key, byte[] ivec, int usage)
        throws KrbException {
        try {
            return Des3.encrypt(key, usage, ivec, data, 0, data.length);
        } catch (GeneralSecurityException e) {
            KrbException ke = new KrbException(e.getMessage());
            ke.initCause(e);
            throw ke;
        }
    }

    public byte[] decrypt(byte[] cipher, byte[] key, int usage)
        throws KrbException{
        byte[] ivec = new byte[blockSize()];
        return decrypt(cipher, key, ivec, usage);
    }

    public byte[] decrypt(byte[] cipher, byte[] key, byte[] iv, int usage)
        throws KrbException {
        try {
            return Des3.decrypt(key, usage, iv, cipher, 0, cipher.length);
        } catch (GeneralSecurityException e) {
            KrbException ke = new KrbException(e.getMessage());
            ke.initCause(e);
            throw ke;
        }
    }

    // Override default, because our decrypted data does not return confounder
    // Should eventually get rid of EncType.decryptedData and
    // EncryptedData.decryptedData altogether
    public byte[] decryptedData(byte[] data) {
        return data;
    }
}
