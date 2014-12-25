package org.apache.kerberos.kerb.crypto;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.GeneralSecurityException;

public class Pbkdf {

    public static byte[] PBKDF2(char[] secret, byte[] salt,
                                   int count, int keySize) throws GeneralSecurityException {

        PBEKeySpec ks = new PBEKeySpec(secret, salt, count, keySize * 8);
        SecretKeyFactory skf =
                SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        SecretKey key = skf.generateSecret(ks);
        byte[] result = key.getEncoded();

        return result;
    }
}
