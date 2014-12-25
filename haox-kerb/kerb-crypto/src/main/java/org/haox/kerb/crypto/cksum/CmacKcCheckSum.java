package org.haox.kerb.crypto.cksum;

import org.haox.kerb.crypto.Cmac;
import org.haox.kerb.crypto.enc.EncryptProvider;
import org.haox.kerb.KrbException;

public abstract class CmacKcCheckSum extends KcCheckSum {

    public CmacKcCheckSum(EncryptProvider encProvider, int computeSize, int outputSize) {
        super(encProvider, null, computeSize, outputSize);
    }

    protected byte[] mac(byte[] Kc, byte[] data, int start, int len) throws KrbException {
        byte[] mac = Cmac.cmac(encProvider(), Kc, data, start, len);
        return mac;
    }
}
