package org.apache.kerberos.kerb.crypto.cksum;

import org.apache.kerberos.kerb.crypto.enc.provider.Des3Provider;
import org.apache.kerberos.kerb.crypto.key.Des3KeyMaker;
import org.apache.kerberos.kerb.spec.common.CheckSumType;

public class HmacSha1Des3CheckSum extends HmacKcCheckSum {

    public HmacSha1Des3CheckSum() {
        super(new Des3Provider(), 20, 20);

        keyMaker(new Des3KeyMaker(encProvider()));
    }

    public int confounderSize() {
        return 8;
    }

    public CheckSumType cksumType() {
        return CheckSumType.HMAC_SHA1_DES3;
    }

    public boolean isSafe() {
        return true;
    }

    public int cksumSize() {
        return 20;  // bytes
    }

    public int keySize() {
        return 24;   // bytes
    }
}
