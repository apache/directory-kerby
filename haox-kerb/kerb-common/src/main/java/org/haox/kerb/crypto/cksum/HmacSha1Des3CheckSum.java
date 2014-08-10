package org.haox.kerb.crypto.cksum;

import org.haox.kerb.crypto.Des3;
import org.haox.kerb.crypto.Hmac;
import org.haox.kerb.crypto.enc.provider.Des3Provider;
import org.haox.kerb.crypto.key.Des3KeyMaker;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.common.CheckSumType;

import java.security.GeneralSecurityException;

public class HmacSha1Des3CheckSum extends HmacKcCheckSum {

    public HmacSha1Des3CheckSum() {
        super(new Des3Provider(), 20, 20);

        keyMaker(new Des3KeyMaker(encProvider()));
    }

    public int confounderSize() {
        return 8;
    }

    public CheckSumType cksumType() {
        return CheckSumType.HMAC_SHA1_DES3;
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
