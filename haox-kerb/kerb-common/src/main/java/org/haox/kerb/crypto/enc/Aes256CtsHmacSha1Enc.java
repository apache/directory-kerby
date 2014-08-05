package org.haox.kerb.crypto.enc;

import org.haox.kerb.crypto.Aes256;
import org.haox.kerb.crypto.enc.provider.Aes256Provider;
import org.haox.kerb.crypto.key.Aes256KeyMaker;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.common.CheckSumType;
import org.haox.kerb.spec.type.common.EncryptionType;

import java.security.GeneralSecurityException;

public final class Aes256CtsHmacSha1Enc extends AesCtsHmacSha1Enc {

    public Aes256CtsHmacSha1Enc() {
        super(new Aes256Provider(), null, new Aes256KeyMaker());
    }

    public EncryptionType eType() {
        return EncryptionType.AES256_CTS_HMAC_SHA1_96;
    }

    public int minimumPadSize() {
        return 0;
    }

    public int confounderSize() {
        return blockSize();
    }

    public CheckSumType checksumType() {
        return CheckSumType.HMAC_SHA1_96_AES256;
    }

    public int checksumSize() {
        return Aes256.getChecksumLength();
    }

    public int blockSize() {
        return 16;
    }

    public int keySize() {
        return 32; // bytes
    }

    public byte[] decryptOld(byte[] cipher, byte[] key, byte[] iv, int usage)
        throws KrbException {
        try {
            return Aes256.decrypt(key, usage, iv, cipher, 0, cipher.length);
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
