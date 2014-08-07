package org.haox.kerb.crypto.key;

import org.haox.kerb.crypto.EncTypeHandler;
import org.haox.kerb.spec.KrbException;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.GeneralSecurityException;

public abstract class AbstractKeyMaker implements KeyMaker {

    protected static final byte[] KERBEROS_CONSTANT = "kerberos".getBytes();

    private EncTypeHandler typeHandler;

    public AbstractKeyMaker(EncTypeHandler typeHandler) {
        this.typeHandler = typeHandler;
    }

    protected EncTypeHandler typeHandler() {
        return typeHandler;
    }

    @Override
    public byte[] random2Key(byte[] randomBits) throws KrbException {
        return new byte[0];
    }

    // DK(Key, Constant) = random-to-key(DR(Key, Constant))
    public byte[] dk(byte[] key, byte[] constant) throws KrbException {
        return random2Key(dr(key, constant));
    }

    protected static char[] makePasswdSalt(String password, String salt) {
        char[] result = new char[password.length() + salt.length()];
        System.arraycopy(password.toCharArray(), 0, result, 0, password.length());
        System.arraycopy(salt.toCharArray(), 0, result, password.length(), salt.length());

        return result;
    }

    protected static byte[] PBKDF2(char[] secret, byte[] salt,
                                   int count, int keySize) throws GeneralSecurityException {

        PBEKeySpec ks = new PBEKeySpec(secret, salt, count, keySize * 8);
        SecretKeyFactory skf =
                SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        SecretKey key = skf.generateSecret(ks);
        byte[] result = key.getEncoded();

        return result;
    }

    /*
     * K1 = E(Key, n-fold(Constant), initial-cipher-state)
     * K2 = E(Key, K1, initial-cipher-state)
     * K3 = E(Key, K2, initial-cipher-state)
     * K4 = ...
     * DR(Key, Constant) = k-truncate(K1 | K2 | K3 | K4 ...)
     */
    private byte[] dr(byte[] key, byte[] constant) throws KrbException {

        int blocksize = typeHandler().encProvider().blockSize();
        int keyInuptSize = typeHandler().encProvider().keyInputSize();
        byte[] keyBytes = new byte[keyInuptSize];

        if (constant.length != blocksize) {
            constant = Dk.nfold(constant, blocksize * 8);
        }
        byte[] Ki = constant;

        int n = 0, len;
        while (n < keyInuptSize) {
            typeHandler().encProvider().encrypt(key, Ki);

            if (n + blocksize >= keyInuptSize) {
                System.arraycopy(Ki, 0, keyBytes, n, keyInuptSize - n);
                break;
            }

            System.arraycopy(Ki, 0, keyBytes, n, blocksize);
            n += blocksize;
        }

        return keyBytes;
    }

    protected static final int readBigEndian(byte[] data, int pos, int size) {
        int result = 0;
        int shifter = (size-1) * 8;
        while (size > 0) {
            result += (data[pos] & 0xff) << shifter;
            shifter -= 8;
            pos++;
            size--;
        }
        return result;
    }
}
