package org.haox.kerb.crypto;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;

public class Rc4 {

    private static byte[] L40 = "fortybits".getBytes();

    public static byte[] getSalt(int usage, boolean exportable) {
        int msUsage = convertUsage(usage);
        byte[] salt;

        if (exportable) {
            salt = new byte[14];
            System.arraycopy(L40, 0, salt, 0, 9);
            Util.int2bytesLe(msUsage, salt, 10);
        } else {
            salt = new byte[4];
            Util.int2bytesLe(msUsage, salt, 0);
        }

        return salt;
    }

    public static int convertUsage(int usage) {
        switch (usage) {
            case 3: return 8;
            case 9: return 8;
            case 23: return 13;
            default: return usage;
        }
    }
}
