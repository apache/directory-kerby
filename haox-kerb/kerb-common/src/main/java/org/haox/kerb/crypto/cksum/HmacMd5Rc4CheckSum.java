package org.haox.kerb.crypto.cksum;

import org.haox.kerb.crypto.ArcFourHmac;
import org.haox.kerb.crypto.Rc4;
import org.haox.kerb.crypto.Hmac;
import org.haox.kerb.crypto.cksum.provider.Md5Provider;
import org.haox.kerb.crypto.enc.provider.Rc4Provider;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.common.CheckSumType;

import java.security.GeneralSecurityException;

public class HmacMd5Rc4CheckSum extends AbstractKeyedCheckSumTypeHandler {

    public HmacMd5Rc4CheckSum() {
        super(new Rc4Provider(), new Md5Provider(), 16, 16);
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
    protected void makeKeyedChecksumWith(byte[] workBuffer, int[] workLens,
                                         byte[] data, int start, int size, byte[] key, int usage) throws KrbException {

        byte[] Ksign = null;
        byte[] signKey = "signaturekey".getBytes();
        byte[] newSignKey = new byte[signKey.length + 1];
        System.arraycopy(signKey, 0, newSignKey, 0, signKey.length);
        Ksign = Hmac.hmac(hashProvider(), key, newSignKey);

        byte[] salt = Rc4.getSalt(usage);

        hashProvider().hash(salt);
        hashProvider().hash(data, start, size);
        byte[] hashTmp = hashProvider().output();

        byte[] hmac = Hmac.hmac(hashProvider(), Ksign, hashTmp);
        System.arraycopy(hmac, 0, workBuffer, 0, hmac.length);
    }

    @Override
    public boolean verifyKeyedChecksum(byte[] data,
          byte[] key, int usage, byte[] checksum) throws KrbException {

         try {
             byte[] newCksum = ArcFourHmac.calculateChecksum(key, usage,
                 data, 0, data.length);

             return checksumEqual(checksum, newCksum);
         } catch (GeneralSecurityException e) {
             KrbException ke = new KrbException(e.getMessage());
             ke.initCause(e);
             throw ke;
         }
     }
}
