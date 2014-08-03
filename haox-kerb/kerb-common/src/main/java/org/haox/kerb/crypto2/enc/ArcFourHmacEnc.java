package org.haox.kerb.crypto2.enc;

import org.haox.kerb.crypto2.ArcFourHmac;
import org.haox.kerb.crypto2.Confounder;
import org.haox.kerb.crypto2.enc.provider.Rc4Provider;
import org.haox.kerb.crypto2.key.Rc4KeyMaker;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.common.CheckSumType;
import org.haox.kerb.spec.type.common.EncryptionType;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;

public final class ArcFourHmacEnc extends AbstractEncryptionTypeHandler {

    public ArcFourHmacEnc() {
        super(new Rc4Provider(), null, new Rc4KeyMaker());
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
        int inputLen = workLens[2];

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

        // compute K1
        k1 = new byte[key.length];
        System.arraycopy(key, 0, k1, 0, key.length);

        // get the salt using key usage
        byte[] salt = getSalt(usage);

        byte[] checksum;
        try {
            // compute K2 using K1
            k2 = getHmac(k1, salt);

            // generate checksum using K2
            checksum = getHmac(k2, workBuffer, checksumLen, confounderLen + inputLen);

            // compute K3 using K2 and checksum
            k3 = getHmac(k2, checksum);
        } catch (GeneralSecurityException e) {
            KrbException ke = new KrbException(e.getMessage());
            ke.initCause(e);
            throw ke;
        }

        byte[] tmpEnc = new byte[confounderLen + inputLen];
        System.arraycopy(workBuffer, checksumLen,
                tmpEnc, 0, confounderLen + inputLen);
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

    public byte[] decrypt(byte[] cipher, byte[] key, int usage)
        throws KrbException {
        byte[] ivec = new byte[blockSize()];
        return decrypt(cipher, key, ivec, usage);
    }

    public byte[] decrypt(byte[] cipher, byte[] key, byte[] ivec, int usage)
        throws KrbException {
        try {
            return ArcFourHmac.decrypt(key, usage, ivec, cipher, 0, cipher.length);
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

    /**
     * Get the HMAC-MD5
     */
    protected byte[] getHmac(byte[] key, byte[] data, int start, int len)
            throws GeneralSecurityException {

        SecretKey keyKi = new SecretKeySpec(key, "HmacMD5");
        Mac m = Mac.getInstance("HmacMD5");
        m.init(keyKi);

        // generate hash
        m.update(data, start, len);
        byte[] hash = m.doFinal();
        return hash;
    }

    protected byte[] getHmac(byte[] key, byte[] data)
            throws GeneralSecurityException {

        SecretKey keyKi = new SecretKeySpec(key, "HmacMD5");
        Mac m = Mac.getInstance("HmacMD5");
        m.init(keyKi);

        // generate hash
        byte[] hash = m.doFinal(data);
        return hash;
    }

    // get the salt using key usage
    private byte[] getSalt(int usage) {
        int ms_usage = arcfour_translate_usage(usage);
        byte[] salt = new byte[4];
        salt[0] = (byte)(ms_usage & 0xff);
        salt[1] = (byte)((ms_usage >> 8) & 0xff);
        salt[2] = (byte)((ms_usage >> 16) & 0xff);
        salt[3] = (byte)((ms_usage >> 24) & 0xff);
        return salt;
    }

    // Key usage translation for MS
    private int arcfour_translate_usage(int usage) {
        switch (usage) {
            case 3: return 8;
            case 9: return 8;
            case 23: return 13;
            default: return usage;
        }
    }
}
