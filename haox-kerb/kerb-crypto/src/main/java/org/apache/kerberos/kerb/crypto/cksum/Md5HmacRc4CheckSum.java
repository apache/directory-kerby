package org.apache.kerberos.kerb.crypto.cksum;

import org.apache.kerberos.kerb.crypto.Hmac;
import org.apache.kerberos.kerb.crypto.Rc4;
import org.apache.kerberos.kerb.crypto.cksum.provider.Md5Provider;
import org.apache.kerberos.kerb.crypto.enc.provider.Rc4Provider;
import org.apache.kerberos.kerb.KrbException;
import org.apache.kerberos.kerb.spec.common.CheckSumType;

public class Md5HmacRc4CheckSum extends AbstractKeyedCheckSumTypeHandler {

    public Md5HmacRc4CheckSum() {
        super(new Rc4Provider(), new Md5Provider(), 16, 16);
    }

    public int confounderSize() {
        return 8;
    }

    public CheckSumType cksumType() {
        return CheckSumType.MD5_HMAC_ARCFOUR;
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

        byte[] Ksign = key;

        byte[] salt = Rc4.getSalt(usage, false);

        hashProvider().hash(salt);
        hashProvider().hash(data, start, len);
        byte[] hashTmp = hashProvider().output();

        byte[] hmac = Hmac.hmac(hashProvider(), Ksign, hashTmp);
        return hmac;
    }
}
