package org.haox.kerb.crypto.enc;

import org.haox.kerb.crypto.Aes256;
import org.haox.kerb.crypto.enc.provider.Aes256Provider;
import org.haox.kerb.crypto.key.Aes256KeyMaker;
import org.haox.kerb.spec.type.common.CheckSumType;
import org.haox.kerb.spec.type.common.EncryptionType;

public class Aes256CtsHmacSha1Enc extends AesCtsHmacSha1Enc {

    public Aes256CtsHmacSha1Enc() {
        super(new Aes256Provider(), null);
        keyMaker(new Aes256KeyMaker(this));
    }

    public EncryptionType eType() {
        return EncryptionType.AES256_CTS_HMAC_SHA1_96;
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

    public byte[] decryptedData(byte[] data) {
        return data;
    }
}
