package org.haox.kerb.crypto.cksum;

import org.haox.kerb.crypto.Hmac;
import org.haox.kerb.crypto.cksum.provider.Sha1Provider;
import org.haox.kerb.crypto.enc.EncryptProvider;
import org.haox.kerb.spec.KrbException;

public abstract class HmacKcCheckSum extends AbstractKeyedCheckSumTypeHandler {

    public HmacKcCheckSum(EncryptProvider encProvider, int computeSize, int outputSize) {
        super(encProvider, new Sha1Provider(), computeSize, outputSize);
    }

    @Override
    protected byte[] makeKeyedChecksumWith(byte[] data, int start, int len,
                                           byte[] key, int usage) throws KrbException {
        byte[] Kc;
        byte[] constant = new byte[5];
        constant[0] = (byte) ((usage>>24)&0xff);
        constant[1] = (byte) ((usage>>16)&0xff);
        constant[2] = (byte) ((usage>>8)&0xff);
        constant[3] = (byte) (usage&0xff);
        constant[4] = (byte) 0x99;
        Kc = keyMaker().dk(key, constant);

        byte[] hmac = Hmac.hmac(hashProvider(), Kc, data, start, len);
        return hmac;
    }
}
