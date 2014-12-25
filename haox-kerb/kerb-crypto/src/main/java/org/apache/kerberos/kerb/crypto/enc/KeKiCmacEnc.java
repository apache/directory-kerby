package org.apache.kerberos.kerb.crypto.enc;

import org.apache.kerberos.kerb.crypto.Cmac;
import org.apache.kerberos.kerb.KrbException;

public abstract class KeKiCmacEnc extends KeKiEnc {

    public KeKiCmacEnc(EncryptProvider encProvider) {
        super(encProvider, null);
    }

    @Override
    public int paddingSize() {
        return 0;
    }

    @Override
    public int checksumSize() {
        return encProvider().blockSize();
    }

    @Override
    protected byte[] makeChecksum(byte[] key, byte[] data, int hashSize)
            throws KrbException {

        // generate hash
        byte[] hash = Cmac.cmac(encProvider(), key, data);

        // truncate hash
        byte[] output = new byte[hashSize];
        System.arraycopy(hash, 0, output, 0, hashSize);
        return output;
    }
}
