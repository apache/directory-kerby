package org.haox.kerb.crypto.enc;

import org.haox.kerb.crypto.cksum.provider.Sha1Provider;
import org.haox.kerb.crypto.enc.provider.Aes256Provider;
import org.haox.kerb.crypto.enc.provider.AesProvider;
import org.haox.kerb.crypto.key.AesKeyMaker;
import org.haox.kerb.spec.type.common.CheckSumType;
import org.haox.kerb.spec.type.common.EncryptionType;

public class Camellia256CtsCmacEnc extends KeKiHmacSha1Enc {

    public Camellia256CtsCmacEnc() {
        super(new Aes256Provider(), new Sha1Provider());
        keyMaker(new AesKeyMaker((AesProvider) encProvider()));
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
