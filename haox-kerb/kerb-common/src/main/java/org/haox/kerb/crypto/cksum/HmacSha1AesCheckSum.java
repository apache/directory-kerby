package org.haox.kerb.crypto.cksum;

import org.haox.kerb.crypto.Aes128;
import org.haox.kerb.crypto.cksum.provider.Sha1Provider;
import org.haox.kerb.crypto.dk.AesDkCrypto;
import org.haox.kerb.crypto.enc.EncryptProvider;
import org.haox.kerb.spec.KrbException;

import java.security.GeneralSecurityException;
import java.util.Arrays;

public abstract class HmacSha1AesCheckSum extends AbstractKeyedCheckSumTypeHandler {
    private AesDkCrypto CRYPTO;

    public HmacSha1AesCheckSum(EncryptProvider encProvider) {
        super(encProvider, new Sha1Provider(), 20, 12);

        CRYPTO = new AesDkCrypto(encProvider.keySize() * 8);
    }

    @Override
    protected void makeKeyedChecksumWith(byte[] workBuffer, int[] workLens, byte[] data,
                                         int start, int len, byte[] key, int usage) throws KrbException {

        /*
        // Derive keys
        byte[] constant = new byte[5];
        constant[0] = (byte) ((usage>>24)&0xff);
        constant[1] = (byte) ((usage>>16)&0xff);
        constant[2] = (byte) ((usage>>8)&0xff);
        constant[3] = (byte) (usage&0xff);

        constant[4] = (byte) 0x99;

        byte[] Kc = dk(baseKey, constant);  // Checksum key

        try {
            // Generate checksum
            // H1 = HMAC(Kc, input)
            byte[] hmac = getHmac(Kc, input);

            if (hmac.length == getChecksumLength()) {
                return hmac;
            } else if (hmac.length > getChecksumLength()) {
                byte[] buf = new byte[getChecksumLength()];
                System.arraycopy(hmac, 0, buf, 0, buf.length);
                return buf;
            } else {
                throw new GeneralSecurityException("checksum size too short: " +
                        hmac.length + "; expecting : " + getChecksumLength());
            }
        } finally {
            Arrays.fill(Kc, 0, Kc.length, (byte) 0);
        }
        */
    }

    public byte[] makeKeyedChecksumOld(byte[] data, byte[] key, int usage) throws KrbException {

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
