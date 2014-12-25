package org.haox.kerb.crypto.cksum;

import org.haox.kerb.crypto.Hmac;
import org.haox.kerb.crypto.cksum.provider.Sha1Provider;
import org.haox.kerb.crypto.enc.EncryptProvider;
import org.haox.kerb.KrbException;

public abstract class HmacKcCheckSum extends KcCheckSum {

    public HmacKcCheckSum(EncryptProvider encProvider, int computeSize, int outputSize) {
        super(encProvider, new Sha1Provider(), computeSize, outputSize);
    }

    protected byte[] mac(byte[] Kc, byte[] data, int start, int len) throws KrbException {
        byte[] hmac = Hmac.hmac(hashProvider(), Kc, data, start, len);
        return hmac;
    }
}
