package org.haox.kerb.crypto.enc;

import org.haox.kerb.crypto.cksum.provider.Sha1Provider;
import org.haox.kerb.crypto.enc.provider.Aes256Provider;
import org.haox.kerb.crypto.key.Aes256KeyMaker;
import org.haox.kerb.spec.type.common.CheckSumType;
import org.haox.kerb.spec.type.common.EncryptionType;

public class Aes256CtsHmacSha1Enc extends KeKiKcHmacSha1Enc {

    public Aes256CtsHmacSha1Enc() {
        super(new Aes256Provider(), new Sha1Provider());
        keyMaker(new Aes256KeyMaker(this.encProvider()));
    }

    public EncryptionType eType() {
        return EncryptionType.AES256_CTS_HMAC_SHA1_96;
    }

    public CheckSumType checksumType() {
        return CheckSumType.HMAC_SHA1_96_AES256;
    }

    @Override
    public int checksumSize() {
        return 96 / 8;
    }
}
