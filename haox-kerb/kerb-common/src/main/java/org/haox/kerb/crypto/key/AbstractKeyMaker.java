package org.haox.kerb.crypto.key;

import org.haox.kerb.crypto.enc.EncryptProvider;
import org.haox.kerb.spec.KrbException;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.UnsupportedEncodingException;
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

    protected static char[] makePasswdSalt(String password, String salt) {
        char[] result = new char[password.length() + salt.length()];
        System.arraycopy(password.toCharArray(), 0, result, 0, password.length());
        System.arraycopy(salt.toCharArray(), 0, result, password.length(), salt.length());

        return result;
    }

    protected static int getIterCount(byte[] param, int defCount) {
        int iterCount = defCount;

        if (param != null) {
            if (param.length != 4) {
                throw new IllegalArgumentException("Invalid param to str2Key");
            }
            iterCount = readBigEndian(param, 0, 4);
        }

        return iterCount;
    }

    protected static byte[] getSaltBytes(String salt, String pepper)
            throws UnsupportedEncodingException {
        byte[] saltBytes = salt.getBytes("UTF-8");
        if (pepper != null && ! pepper.isEmpty()) {
            byte[] pepperBytes = pepper.getBytes("UTF-8");
            int len = saltBytes.length;
            len += 1 + pepperBytes.length;
            byte[] results = new byte[len];
            System.arraycopy(pepperBytes, 0, results, 0, pepperBytes.length);
            results[pepperBytes.length] = (byte) 0;
            System.arraycopy(saltBytes, 0,
                    results, pepperBytes.length + 1, saltBytes.length);

            return results;
        } else {
            return saltBytes;
        }
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
