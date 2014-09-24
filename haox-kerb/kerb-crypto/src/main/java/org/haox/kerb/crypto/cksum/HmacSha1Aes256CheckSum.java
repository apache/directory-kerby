package org.haox.kerb.crypto.cksum;

import org.haox.kerb.crypto.enc.provider.Aes256Provider;
import org.haox.kerb.crypto.key.AesKeyMaker;
import org.haox.kerb.spec.type.common.CheckSumType;

public class HmacSha1Aes256CheckSum extends HmacKcCheckSum {

    public HmacSha1Aes256CheckSum() {
        super(new Aes256Provider(), 20, 12);

        keyMaker(new AesKeyMaker((Aes256Provider) encProvider()));
    }

    public int confounderSize() {
        return 16;
    }

    public CheckSumType cksumType() {
        return CheckSumType.HMAC_SHA1_96_AES256;
    }

    public boolean isSafe() {
        return true;
    }

    public int cksumSize() {
        return 12;  // bytes
    }

    public int keySize() {
        return 32;   // bytes
    }
}
