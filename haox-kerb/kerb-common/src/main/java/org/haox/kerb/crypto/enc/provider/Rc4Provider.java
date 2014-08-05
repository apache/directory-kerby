package org.haox.kerb.crypto.enc.provider;

import org.haox.kerb.spec.KrbException;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;

public class Rc4Provider extends AbstractEncryptProvider {

    public Rc4Provider() {
        super(1, 16, 16);
    }

    @Override
    public void encrypt(byte[] key, byte[] cipherState, byte[] data) throws KrbException {
        rc4Encrypt(data, key, cipherState, true);
    }

    @Override
    public void decrypt(byte[] key, byte[] cipherState, byte[] data) throws KrbException {
        rc4Encrypt(data, key, cipherState, false);
    }

    @Override
    public byte[] initState(byte[] key, int keyUsage) {
        return new byte[0];
    }

    public static void rc4Encrypt(byte[] data, byte[] key,
                                  byte[] cipherState, boolean encrypt) throws KrbException {
        try {
            Cipher cipher = Cipher.getInstance("ARCFOUR");
            SecretKeySpec secretKey = new SecretKeySpec(key, "ARCFOUR");
            cipher.init(encrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE, secretKey);
            byte[] output = cipher.doFinal(data);
            System.arraycopy(output, 0, data, 0, output.length);
        } catch (GeneralSecurityException e) {
            KrbException ke = new KrbException(e.getMessage());
            ke.initCause(e);
            throw ke;
        }

    }
}
