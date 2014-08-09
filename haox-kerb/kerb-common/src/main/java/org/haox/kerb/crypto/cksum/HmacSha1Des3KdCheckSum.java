package org.haox.kerb.crypto.cksum;

import org.haox.kerb.crypto.Des3;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.common.CheckSumType;

import java.security.GeneralSecurityException;

public class HmacSha1Des3KdCheckSum extends AbstractKeyedCheckSumTypeHandler {

    public HmacSha1Des3KdCheckSum() {
        super(null, null, 20, 20);
    }

    public int confounderSize() {
        return 8;
    }

    public CheckSumType cksumType() {
        return CheckSumType.HMAC_SHA1_DES3_KD;
    }

    public boolean isSafe() {
        return true;
    }

    public int cksumSize() {
        return 20;  // bytes
    }

    public int keySize() {
        return 24;   // bytes
    }

    @Override
    public byte[] makeKeyedChecksum(byte[] data, byte[] key, int usage) throws KrbException {

         try {
             return Des3.calculateChecksum(key, usage, data, 0, data.length);
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
             byte[] newCksum = Des3.calculateChecksum(key, usage,
                 data, 0, data.length);

             return checksumEqual(checksum, newCksum);
         } catch (GeneralSecurityException e) {
             KrbException ke = new KrbException(e.getMessage());
             ke.initCause(e);
             throw ke;
         }
     }
}
