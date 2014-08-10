package org.haox.kerb.crypto.key;

import org.haox.kerb.crypto.enc.EncryptProvider;
import org.haox.kerb.spec.KrbException;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.security.GeneralSecurityException;

public abstract class AbstractKeyMaker implements KeyMaker {

    protected static final byte[] KERBEROS_CONSTANT = "kerberos".getBytes();

    private EncryptProvider encProvider;

    public AbstractKeyMaker(EncryptProvider encProvider) {
        this.encProvider = encProvider;
    }

    protected EncryptProvider encProvider() {
        return encProvider;
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

        int blocksize = encProvider().blockSize();
        int keyInuptSize = encProvider().keyInputSize();
        byte[] keyBytes = new byte[keyInuptSize];
        byte[] Ki;

        if (constant.length != blocksize) {
            Ki = Dk.nfold(constant, blocksize);
        } else {
            Ki = new byte[constant.length];
            System.arraycopy(constant, 0, Ki, 0, constant.length);
        }

        int n = 0, len;
        while (n < keyInuptSize) {
            encProvider().encrypt(key, Ki);

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

    // Routines used for debugging
    static String bytesToString(byte[] digest) {
        // Get character representation of digest
        StringBuffer digestString = new StringBuffer();

        for (int i = 0; i < digest.length; i++) {
            if ((digest[i] & 0x000000ff) < 0x10) {
                digestString.append("0" +
                        Integer.toHexString(digest[i] & 0x000000ff));
            } else {
                digestString.append(
                        Integer.toHexString(digest[i] & 0x000000ff));
            }
        }
        return digestString.toString();
    }

    protected static byte[] binaryStringToBytes(String str) {
        char[] usageStr = str.toCharArray();
        byte[] usage = new byte[usageStr.length/2];
        for (int i = 0; i < usage.length; i++) {
            byte a = Byte.parseByte(new String(usageStr, i*2, 1), 16);
            byte b = Byte.parseByte(new String(usageStr, i*2 + 1, 1), 16);
            usage[i] = (byte) ((a<<4)|b);
        }
        return usage;
    }

    protected static byte[] charToUtf16(char[] chars) {
        Charset utf8 = Charset.forName("UTF-16LE");

        CharBuffer cb = CharBuffer.wrap(chars);
        ByteBuffer bb = utf8.encode(cb);
        int len = bb.limit();
        byte[] answer = new byte[len];
        bb.get(answer, 0, len);
        return answer;
    }
}
