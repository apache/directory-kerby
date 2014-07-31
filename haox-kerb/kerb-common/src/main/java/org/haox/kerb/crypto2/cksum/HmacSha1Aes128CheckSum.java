package org.haox.kerb.crypto2.cksum;

import org.haox.kerb.crypto2.Aes128;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.common.CheckSumType;

import java.security.GeneralSecurityException;

public class HmacSha1Aes128CheckSum extends AbstractCheckSumTypeHandler {

    public HmacSha1Aes128CheckSum() {
    }

    public int confounderSize() {
        return 16;
    }

    public CheckSumType cksumType() {
        return CheckSumType.HMAC_SHA1_96_AES128;
    }

    public boolean isSafe() {
        return true;
    }

    public int cksumSize() {
        return 12;  // bytes
    }

    public int keySize() {
        return 16;   // bytes
    }

    @Override
    public byte[] calculateKeyedChecksum(byte[] data, byte[] key, int usage) throws KrbException {

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
            return isChecksumEqual(checksum, newCksum);
         } catch (GeneralSecurityException e) {
            KrbException ke = new KrbException(e.getMessage());
            ke.initCause(e);
            throw ke;
         }
    }
}
