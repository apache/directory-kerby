package org.haox.kerb.crypto.cksum;

import org.haox.kerb.crypto.Aes256;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.common.CheckSumType;

import java.security.GeneralSecurityException;

public class HmacSha1Aes256CheckSum extends AbstractKeyedCheckSumTypeHandler {

    public HmacSha1Aes256CheckSum() {
        super(null, null);
    }

    public int confounderSize() {
        return 16;
    }

    public CheckSumType cksumType() {
        return CheckSumType.HMAC_SHA1_96_AES256;
    }

    public boolean isSafe() {
        return true;
    }

    public int cksumSize() {
        return 12;  // bytes
    }

    public int keySize() {
        return 32;   // bytes
    }

    @Override
    public byte[] calculateKeyedChecksum(byte[] data, byte[] key, int usage) throws KrbException {

         try {
            return Aes256.calculateChecksum(key, usage, data, 0, data.length);
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
            byte[] newCksum = Aes256.calculateChecksum(key, usage, data,
                    0, data.length);
            return checksumEqual(checksum, newCksum);
         } catch (GeneralSecurityException e) {
            KrbException ke = new KrbException(e.getMessage());
            ke.initCause(e);
            throw ke;
         }
    }
}
