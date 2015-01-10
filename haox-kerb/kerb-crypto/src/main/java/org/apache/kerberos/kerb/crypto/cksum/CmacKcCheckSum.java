package org.apache.kerberos.kerb.crypto.cksum;

import org.apache.kerberos.kerb.crypto.Cmac;
import org.apache.kerberos.kerb.crypto.enc.EncryptProvider;
import org.apache.kerberos.kerb.KrbException;

public abstract class CmacKcCheckSum extends KcCheckSum {

    public CmacKcCheckSum(EncryptProvider encProvider, int computeSize, int outputSize) {
        super(encProvider, null, computeSize, outputSize);
    }

    protected byte[] mac(byte[] Kc, byte[] data, int start, int len) throws KrbException {
        byte[] mac = Cmac.cmac(encProvider(), Kc, data, start, len);
        return mac;
    }
}
