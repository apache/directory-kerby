package org.haox.kerb.crypto;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;

public class Rc4 {

    public static byte[] getSalt(int usage) {
        int ms_usage = convertUsage(usage);
        byte[] salt = new byte[4];
        salt[0] = (byte)(ms_usage & 0xff);
        salt[1] = (byte)((ms_usage >> 8) & 0xff);
        salt[2] = (byte)((ms_usage >> 16) & 0xff);
        salt[3] = (byte)((ms_usage >> 24) & 0xff);
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
