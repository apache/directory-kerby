package org.haox.kerb.crypto.enc;

import org.haox.kerb.crypto.Aes128;
import org.haox.kerb.crypto.cksum.provider.Sha1Provider;
import org.haox.kerb.crypto.enc.provider.Aes128Provider;
import org.haox.kerb.crypto.key.Aes128KeyMaker;
import org.haox.kerb.spec.type.common.CheckSumType;
import org.haox.kerb.spec.type.common.EncryptionType;

public class Aes128CtsHmacSha1Enc extends KeKiKcHmacSha1Enc {

    public Aes128CtsHmacSha1Enc() {
        super(new Aes128Provider(), new Sha1Provider());
        keyMaker(new Aes128KeyMaker(this));
    }

    @Override
    public int checksumSize() {
        return 96 / 8;
    }

    public EncryptionType eType() {
        return EncryptionType.AES128_CTS_HMAC_SHA1_96;
    }

    public CheckSumType checksumType() {
        return CheckSumType.HMAC_SHA1_96_AES128;
    }
}
