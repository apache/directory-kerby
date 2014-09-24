package org.haox.kerb.crypto.enc.provider;

import org.haox.kerb.spec.KrbException;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;

public class DesProvider extends AbstractEncryptProvider {

    public DesProvider() {
        super(8, 7, 8);
    }

    @Override
    protected void doEncrypt(byte[] input, byte[] key,
                                 byte[] cipherState, boolean encrypt) throws KrbException {

        Cipher cipher = null;
        try {
            cipher = Cipher.getInstance("DES/CBC/NoPadding");
        } catch (GeneralSecurityException e) {
            throw new KrbException("Failed to init cipher", e);
        }
        IvParameterSpec params = new IvParameterSpec(cipherState);
        SecretKeySpec skSpec = new SecretKeySpec(key, "DES");
        try {
            SecretKeyFactory skf = SecretKeyFactory.getInstance("DES");
            SecretKey sk = (SecretKey) skSpec;

            cipher.init(encrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE, sk, params);

            byte[] output = cipher.doFinal(input);
            System.arraycopy(output, 0, input, 0, output.length);
        } catch (GeneralSecurityException e) {
            KrbException ke = new KrbException(e.getMessage());
            ke.initCause(e);
            throw ke;
        }
    }

    @Override
    public byte[] cbcMac(byte[] key, byte[] cipherState, byte[] data) throws KrbException {
        Cipher cipher = null;
        try {
            cipher = Cipher.getInstance("DES/CBC/NoPadding");
        } catch (GeneralSecurityException e) {
            throw new KrbException("Failed to init cipher", e);
        }
        IvParameterSpec params = new IvParameterSpec(cipherState);
        SecretKeySpec skSpec = new SecretKeySpec(key, "DES");

        byte[] output = null;
        try {
            SecretKeyFactory skf = SecretKeyFactory.getInstance("DES");
            // SecretKey sk = skf.generateSecret(skSpec);
            SecretKey sk = (SecretKey) skSpec;
            cipher.init(Cipher.ENCRYPT_MODE, sk, params);
            for (int i = 0; i < data.length / 8; i++) {
                output = cipher.doFinal(data, i * 8, 8);
                cipher.init(Cipher.ENCRYPT_MODE, sk, (new IvParameterSpec(output)));
            }
        }
        catch (GeneralSecurityException e) {
            KrbException ke = new KrbException(e.getMessage());
            ke.initCause(e);
            throw ke;
        }
        return output;
    }

    @Override
    public boolean supportCbcMac() {
        return true;
    }
}
