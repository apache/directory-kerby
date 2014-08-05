package org.haox.kerb.crypto.cksum;

import org.haox.kerb.crypto.Aes128;
import org.haox.kerb.crypto.dk.AesDkCrypto;
import org.haox.kerb.crypto.enc.EncryptProvider;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.common.CheckSumType;

import java.security.GeneralSecurityException;

public abstract class HmacSha1AesCheckSum extends AbstractKeyedCheckSumTypeHandler {
    private AesDkCrypto CRYPTO;

    public HmacSha1AesCheckSum(EncryptProvider encProvider,
                               HashProvider hashProvider) {
        super(encProvider, hashProvider, 20, 12);

        CRYPTO = new AesDkCrypto(encProvider.keySize() * 8);
    }

    @Override
    public byte[] makeKeyedChecksum(byte[] data, byte[] key, int usage) throws KrbException {

         try {
            return Aes128.calculateChecksum(key, usage, data, 0, data.length);
         } catch (GeneralSecurityException e) {
            KrbException ke = new KrbException(e.getMessage());
            ke.initCause(e);
            throw ke;
         }
    }

    @Override
    public boolean verifyKeyedChecksum(byte[] data,
        byte[] key, int usage, byte[] checksum) throws KrbException {

         try {
            byte[] newCksum = Aes128.calculateChecksum(key, usage,
                                                        data, 0, data.length);
            return checksumEqual(checksum, newCksum);
         } catch (GeneralSecurityException e) {
            KrbException ke = new KrbException(e.getMessage());
            ke.initCause(e);
            throw ke;
         }
    }
}
