package org.haox.kerb.crypto.enc.provider;

import org.haox.kerb.spec.KrbException;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;

public abstract class AesProvider extends AbstractEncryptProvider {

    public AesProvider(int blockSize, int keyInputSize, int keySize) {
        super(blockSize, keyInputSize, keySize);
    }

    @Override
    public void encrypt(byte[] key, byte[] cipherState, byte[] data) throws KrbException {
        aesEncrypt(data, key, cipherState, true);
    }

    @Override
    public void decrypt(byte[] key, byte[] cipherState, byte[] data) throws KrbException {
        aesEncrypt(data, key, cipherState, false);
    }

    @Override
    public byte[] initState(byte[] key, int keyUsage) {
        return new byte[0];
    }

    public static void aesEncrypt(byte[] input, byte[] key,
                                  byte[] cipherState, boolean encrypt) throws KrbException {
        Cipher cipher = null;
        try {
            cipher = Cipher.getInstance("AES/CTS/NoPadding");
        } catch (GeneralSecurityException e) {
            KrbException ke = new KrbException("JCE provider may not be installed. "
                    + e.getMessage());
            ke.initCause(e);
            throw ke;
        }

        try {
            SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
            IvParameterSpec param = new IvParameterSpec(cipherState);

            cipher.init(encrypt ?
                    Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE, secretKey, param);
            byte[] output = cipher.doFinal(input);
            System.arraycopy(output, 0, input, 0, output.length);
        } catch (GeneralSecurityException e) {
            KrbException ke = new KrbException(e.getMessage());
            ke.initCause(e);
            throw ke;
        }
    }
}
