package org.haox.kerb.crypto.enc;

import org.haox.kerb.crypto.ArcFourHmac;
import org.haox.kerb.crypto.Confounder;
import org.haox.kerb.crypto.Rc4;
import org.haox.kerb.crypto.cksum.provider.Hmac;
import org.haox.kerb.crypto.cksum.provider.Md5Provider;
import org.haox.kerb.crypto.enc.provider.Rc4Provider;
import org.haox.kerb.crypto.key.Rc4KeyMaker;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.common.CheckSumType;
import org.haox.kerb.spec.type.common.EncryptionType;
import org.haox.kerb.spec.type.common.KrbErrorCode;

import java.security.GeneralSecurityException;

public final class ArcFourHmacEnc extends AbstractEncryptionTypeHandler {

    public ArcFourHmacEnc() {
        super(new Rc4Provider(), new Md5Provider(), new Rc4KeyMaker());
    }

    public EncryptionType eType() {
        return EncryptionType.ARCFOUR_HMAC;
    }

    public int minimumPadSize() {
        return 1;
    }

    @Override
    public int confounderSize() {
        return 8;
    }

    @Override
    public int paddingSize() {
        return 0;
    }

    public CheckSumType checksumType() {
        return CheckSumType.HMAC_MD5_ARCFOUR;
    }

    public int checksumSize() {
        return ArcFourHmac.getChecksumLength();
    }

    public int blockSize() {
        return 1;
    }

    public int keySize() {
        return 16; // bytes
    }

    protected void encryptWith(byte[] workBuffer, int[] workLens,
         byte[] key, byte[] iv, int usage) throws KrbException {
        int confounderLen = workLens[0];
        int checksumLen = workLens[1];
        int dataLen = workLens[2];

        /**
         * Instead of E(Confounder | Checksum | Plaintext | Padding),
         * Checksum | E(Confounder | Plaintext)
         */

        // confounder
        byte[] confounder = Confounder.bytes(confounderLen);
        System.arraycopy(confounder, 0, workBuffer, checksumLen, confounderLen);

        // no padding

        /* checksum and encryption */

        byte[] k1, k2, k3;

        k1 = new byte[key.length];
        System.arraycopy(key, 0, k1, 0, key.length);

        byte[] checksum;
        byte[] salt = Rc4.getSalt(usage);
        k2 = Hmac.hmac(hashProvider(), k1, salt);

        checksum = Hmac.hmac(hashProvider(), k2, workBuffer,
                checksumLen, confounderLen + dataLen);

        k3 = Hmac.hmac(hashProvider(), k2, checksum);

        byte[] tmpEnc = new byte[confounderLen + dataLen];
        System.arraycopy(workBuffer, checksumLen,
                tmpEnc, 0, confounderLen + dataLen);
        encProvider().encrypt(k3, iv, tmpEnc);
        System.arraycopy(checksum, 0, workBuffer, 0, checksumLen);
        System.arraycopy(tmpEnc, 0, workBuffer, checksumLen, tmpEnc.length);
    }

    public byte[] encryptOld(byte[] data, byte[] key, byte[] iv, int usage)
        throws KrbException {
        try {
            return ArcFourHmac.encrypt(key, usage, iv, data, 0, data.length);
        } catch (GeneralSecurityException e) {
            KrbException ke = new KrbException(e.getMessage());
            ke.initCause(e);
            throw ke;
        }
    }

    @Override
    protected byte[] decryptWith(byte[] workBuffer, int[] workLens,
                                 byte[] key, byte[] iv, int usage) throws KrbException {
        int confounderLen = workLens[0];
        int checksumLen = workLens[1];
        int dataLen = workLens[2];

        /* checksum and decryption */

        byte[] k1, k2, k3;

        k1 = new byte[key.length];
        System.arraycopy(key, 0, k1, 0, key.length);

        byte[] salt = Rc4.getSalt(usage);

        k2 = Hmac.hmac(hashProvider(), k1, salt);

        k3 = Hmac.hmac(hashProvider(), k2, workBuffer, 0, checksumLen);

        byte[] tmpEnc = new byte[confounderLen + dataLen];
        System.arraycopy(workBuffer, checksumLen,
                tmpEnc, 0, confounderLen + dataLen);
        encProvider().decrypt(k3, iv, tmpEnc);

        byte[] newChecksum = Hmac.hmac(hashProvider(), k2, tmpEnc);

        if (! checksumEqual(workBuffer, newChecksum, newChecksum.length)) {
            throw new KrbException(KrbErrorCode.KRB_AP_ERR_BAD_INTEGRITY);
        }

        byte[] data = new byte[dataLen];
        System.arraycopy(tmpEnc, confounderLen,
                data, 0, dataLen);

        return data;

    }

    public byte[] decryptOld(byte[] cipher, byte[] key, byte[] iv, int usage)
        throws KrbException {
        try {
            return ArcFourHmac.decrypt(key, usage, iv, cipher, 0, cipher.length);
        } catch (GeneralSecurityException e) {
            KrbException ke = new KrbException(e.getMessage());
            ke.initCause(e);
            throw ke;
        }
    }

    // Override default, because our decrypted data does not return confounder
    // Should eventually get rid of EncType.decryptedData and
    // EncryptedData.decryptedData altogether
    public byte[] decryptedData(byte[] data) {
        return data;
    }
}
