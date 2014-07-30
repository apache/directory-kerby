package org.haox.kerb.crypto2;

import org.haox.kerb.crypto2.dk.AesDkCrypto;
import org.haox.kerb.spec.KrbException;

import java.security.GeneralSecurityException;

public class Aes128 {
    private static final AesDkCrypto CRYPTO = new AesDkCrypto(128);

    private Aes128() {
    }

    public static byte[] stringToKey(char[] password, String salt, byte[] params)
        throws GeneralSecurityException {
        return CRYPTO.stringToKey(password, salt, params);
    }

    // in bytes
    public static int getChecksumLength() {
        return CRYPTO.getChecksumLength();
    }

    public static byte[] calculateChecksum(byte[] baseKey, int usage,
        byte[] input, int start, int len) throws GeneralSecurityException {
            return CRYPTO.calculateChecksum(baseKey, usage, input, start, len);
    }

    public static byte[] encrypt(byte[] baseKey, int usage,
        byte[] ivec, byte[] plaintext, int start, int len)
        throws GeneralSecurityException, KrbException {
            return CRYPTO.encrypt(baseKey, usage, ivec, null /* new_ivec */,
                plaintext, start, len);
    }

    /* Encrypt plaintext; do not add confounder, or checksum */
    public static byte[] encryptRaw(byte[] baseKey, int usage,
        byte[] ivec, byte[] plaintext, int start, int len)
        throws GeneralSecurityException, KrbException {
        return CRYPTO.encryptRaw(baseKey, usage, ivec, plaintext, start, len);
    }

    public static byte[] decrypt(byte[] baseKey, int usage, byte[] ivec,
        byte[] ciphertext, int start, int len)
        throws GeneralSecurityException {
        return CRYPTO.decrypt(baseKey, usage, ivec, ciphertext, start, len);
    }

    /* Decrypt ciphertext; do not remove confounder, or check checksum */
    public static byte[] decryptRaw(byte[] baseKey, int usage, byte[] ivec,
        byte[] ciphertext, int start, int len)
        throws GeneralSecurityException {
        return CRYPTO.decryptRaw(baseKey, usage, ivec, ciphertext, start, len);
    }
};
