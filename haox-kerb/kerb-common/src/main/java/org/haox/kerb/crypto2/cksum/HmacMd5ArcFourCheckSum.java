package org.haox.kerb.crypto2.cksum;

import org.haox.kerb.crypto2.ArcFourHmac;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.common.CheckSumType;

import java.security.GeneralSecurityException;

public class HmacMd5ArcFourCheckSum extends AbstractCheckSumTypeHandler {

    public HmacMd5ArcFourCheckSum() {
    }

    public int confounderSize() {
        return 8;
    }

    public CheckSumType cksumType() {
        return CheckSumType.HMAC_MD5_ARCFOUR;
    }

    public boolean isSafe() {
        return true;
    }

    public int cksumSize() {
        return 16;  // bytes
    }

    public int keySize() {
        return 16;   // bytes
    }

    @Override
    public byte[] calculateKeyedChecksum(byte[] data, byte[] key, int usage) throws KrbException {

         try {
             return ArcFourHmac.calculateChecksum(key, usage, data, 0, data.length);
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
             byte[] newCksum = ArcFourHmac.calculateChecksum(key, usage,
                 data, 0, data.length);

             return isChecksumEqual(checksum, newCksum);
         } catch (GeneralSecurityException e) {
             KrbException ke = new KrbException(e.getMessage());
             ke.initCause(e);
             throw ke;
         }
     }
}
