package org.haox.kerb.crypto.enc;

import org.haox.kerb.crypto.Hmac;
import org.haox.kerb.crypto.cksum.HashProvider;
import org.haox.kerb.spec.KrbException;

public abstract class KeKiHmacSha1Enc extends KeKiEnc {

    public KeKiHmacSha1Enc(EncryptProvider encProvider,
                           HashProvider hashProvider) {
        super(encProvider, hashProvider);
    }

    @Override
    public int paddingSize() {
        return 0;
    }

    @Override
    protected byte[] makeChecksum(byte[] key, byte[] data, int hashSize)
            throws KrbException {

        // generate hash
        byte[] hash = Hmac.hmac(hashProvider(), key, data);

        // truncate hash
        byte[] output = new byte[hashSize];
        System.arraycopy(hash, 0, output, 0, hashSize);
        return output;
    }
}
