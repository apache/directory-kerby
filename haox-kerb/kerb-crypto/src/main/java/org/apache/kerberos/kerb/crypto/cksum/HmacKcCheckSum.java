package org.apache.kerberos.kerb.crypto.cksum;

import org.apache.kerberos.kerb.crypto.Hmac;
import org.apache.kerberos.kerb.crypto.cksum.provider.Sha1Provider;
import org.apache.kerberos.kerb.crypto.enc.EncryptProvider;
import org.apache.kerberos.kerb.KrbException;

public abstract class HmacKcCheckSum extends KcCheckSum {

    public HmacKcCheckSum(EncryptProvider encProvider, int computeSize, int outputSize) {
        super(encProvider, new Sha1Provider(), computeSize, outputSize);
    }

    protected byte[] mac(byte[] Kc, byte[] data, int start, int len) throws KrbException {
        byte[] hmac = Hmac.hmac(hashProvider(), Kc, data, start, len);
        return hmac;
    }
}
