package org.haox.kerb.crypto.key;

import org.haox.kerb.crypto.BytesUtil;
import org.haox.kerb.crypto.enc.EncryptProvider;
import org.haox.kerb.spec.KrbException;

import java.io.UnsupportedEncodingException;

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
            iterCount = BytesUtil.bytes2int(param, 0, true);
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
}
