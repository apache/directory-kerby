package org.haox.kerb.crypto.cksum;

import org.haox.kerb.crypto.Util;
import org.haox.kerb.crypto.enc.EncryptProvider;
import org.haox.kerb.crypto.key.DkKeyMaker;
import org.haox.kerb.spec.KrbException;

public abstract class KcCheckSum extends AbstractKeyedCheckSumTypeHandler {

    public KcCheckSum(EncryptProvider encProvider, HashProvider hashProvider,
                      int computeSize, int outputSize) {
        super(encProvider, hashProvider, computeSize, outputSize);
    }

    @Override
    protected byte[] doChecksumWithKey(byte[] data, int start, int len,
                                       byte[] key, int usage) throws KrbException {
        byte[] Kc;
        byte[] constant = new byte[5];
        Util.int2bytesBe(usage, constant, 0);
        constant[4] = (byte) 0x99;
        Kc = ((DkKeyMaker) keyMaker()).dk(key, constant);

        byte[] mac = mac(Kc, data, start, len);
        return mac;
    }

    protected abstract byte[] mac(byte[] Kc, byte[] data, int start, int len) throws KrbException;
}
