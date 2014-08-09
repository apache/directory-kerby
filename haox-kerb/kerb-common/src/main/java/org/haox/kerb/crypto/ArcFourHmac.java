package org.haox.kerb.crypto;

import org.haox.kerb.crypto.dk.ArcFourCrypto;
import org.haox.kerb.spec.KrbException;

import java.security.GeneralSecurityException;

public class ArcFourHmac {
    private static final ArcFourCrypto CRYPTO = new ArcFourCrypto(128);

    private ArcFourHmac() {
    }

    public static byte[] stringToKey(char[] password)
        throws GeneralSecurityException {
        return CRYPTO.stringToKey(password);
    }

    // in bytes
    public static int getChecksumLength() {
        return CRYPTO.getChecksumLength();
    }

    public static byte[] calculateChecksum(byte[] baseKey, int usage,
        byte[] input, int start, int len) throws GeneralSecurityException {
            return CRYPTO.calculateChecksum(baseKey, usage, input, start, len);
    }

    /* Encrypt Sequence Number */
    public static byte[] encryptSeq(byte[] baseKey, int usage,
        byte[] checksum, byte[] plaintext, int start, int len)
        throws GeneralSecurityException, KrbException {
        return CRYPTO.encryptSeq(baseKey, usage, checksum, plaintext, start, len);
    }

    /* Decrypt Sequence Number */
    public static byte[] decryptSeq(byte[] baseKey, int usage, byte[] checksum,
        byte[] ciphertext, int start, int len)
        throws GeneralSecurityException, KrbException {
        return CRYPTO.decryptSeq(baseKey, usage, checksum, ciphertext, start, len);
    }

    public static byte[] encrypt(byte[] baseKey, int usage,
        byte[] ivec, byte[] plaintext, int start, int len)
        throws GeneralSecurityException, KrbException {
            return CRYPTO.encrypt(baseKey, usage, ivec, null /* new_ivec */,
                plaintext, start, len);
    }

    /* Encrypt plaintext; do not add confounder, or checksum */
    public static byte[] encryptRaw(byte[] baseKey, int usage,
        byte[] seqNum, byte[] plaintext, int start, int len)
        throws GeneralSecurityException, KrbException {
        return CRYPTO.encryptRaw(baseKey, usage, seqNum, plaintext, start, len);
    }

    public static byte[] decrypt(byte[] baseKey, int usage, byte[] ivec,
        byte[] ciphertext, int start, int len)
        throws GeneralSecurityException {
        return CRYPTO.decrypt(baseKey, usage, ivec, ciphertext, start, len);
    }

    /* Decrypt ciphertext; do not remove confounder, or check checksum */
    public static byte[] decryptRaw(byte[] baseKey, int usage, byte[] ivec,
        byte[] ciphertext, int start, int len, byte[] seqNum)
        throws GeneralSecurityException {
        return CRYPTO.decryptRaw(baseKey, usage, ivec, ciphertext, start, len, seqNum);
    }
};
