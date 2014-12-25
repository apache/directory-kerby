package org.apache.kerberos.kerb.crypto.cksum;

import org.apache.kerberos.kerb.crypto.Hmac;
import org.apache.kerberos.kerb.crypto.Rc4;
import org.apache.kerberos.kerb.crypto.cksum.provider.Md5Provider;
import org.apache.kerberos.kerb.KrbException;
import org.apache.kerberos.kerb.spec.common.CheckSumType;

public class HmacMd5Rc4CheckSum extends AbstractKeyedCheckSumTypeHandler {

    public HmacMd5Rc4CheckSum() {
        super(null, new Md5Provider(), 16, 16);
    }

    public int confounderSize() {
        return 8;
    }

    public CheckSumType cksumType() {
        return CheckSumType.HMAC_MD5_ARCFOUR;
    }

    public boolean isSafe() {
        return true;
    }

    public int cksumSize() {
        return 16;  // bytes
    }

    public int keySize() {
        return 16;   // bytes
    }

    @Override
    protected byte[] doChecksumWithKey(byte[] data, int start, int len,
                                       byte[] key, int usage) throws KrbException {

        byte[] Ksign = null;
        byte[] signKey = "signaturekey".getBytes();
        byte[] newSignKey = new byte[signKey.length + 1];
        System.arraycopy(signKey, 0, newSignKey, 0, signKey.length);
        Ksign = Hmac.hmac(hashProvider(), key, newSignKey);

        byte[] salt = Rc4.getSalt(usage, false);

        hashProvider().hash(salt);
        hashProvider().hash(data, start, len);
        byte[] hashTmp = hashProvider().output();

        byte[] hmac = Hmac.hmac(hashProvider(), Ksign, hashTmp);
        return hmac;
    }
}
