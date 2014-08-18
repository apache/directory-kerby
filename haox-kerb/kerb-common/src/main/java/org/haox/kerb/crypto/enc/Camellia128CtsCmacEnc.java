package org.haox.kerb.crypto.enc;

import org.haox.kerb.crypto.cksum.provider.Sha1Provider;
import org.haox.kerb.crypto.enc.provider.AesProvider;
import org.haox.kerb.crypto.enc.provider.Camellia128Provider;
import org.haox.kerb.crypto.enc.provider.CamelliaProvider;
import org.haox.kerb.crypto.key.CamelliaKeyMaker;
import org.haox.kerb.spec.type.common.CheckSumType;
import org.haox.kerb.spec.type.common.EncryptionType;

public class Camellia128CtsCmacEnc extends KeKiHmacSha1Enc {

    public Camellia128CtsCmacEnc() {
        super(new Camellia128Provider(), new Sha1Provider());
        keyMaker(new CamelliaKeyMaker((Camellia128Provider) encProvider()));
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
