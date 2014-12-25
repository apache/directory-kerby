package org.haox.kerb.crypto.cksum;

import org.haox.kerb.crypto.enc.provider.Aes128Provider;
import org.haox.kerb.crypto.key.AesKeyMaker;
import org.haox.kerb.spec.common.CheckSumType;

public class HmacSha1Aes128CheckSum extends HmacKcCheckSum {

    public HmacSha1Aes128CheckSum() {
        super(new Aes128Provider(), 20, 12);

        keyMaker(new AesKeyMaker((Aes128Provider) encProvider()));
    }

    public int confounderSize() {
        return 16;
    }

    public CheckSumType cksumType() {
        return CheckSumType.HMAC_SHA1_96_AES128;
    }

    public boolean isSafe() {
        return true;
    }

    public int cksumSize() {
        return 12;  // bytes
    }

    public int keySize() {
        return 16;   // bytes
    }
}
