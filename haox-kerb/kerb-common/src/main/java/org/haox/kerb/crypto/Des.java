package org.haox.kerb.crypto;

import javax.crypto.spec.DESKeySpec;
import java.security.InvalidKeyException;

public class Des {

    public static boolean isWeakKey(byte[] key) {
        try {
            return (DESKeySpec.isWeak(key, 0));
        } catch (InvalidKeyException ex) {
            return true;
        }
    }

    public static byte[] fixKey(byte[] key) {
        if (Des.isWeakKey(key)) {
            key[7] ^= 0xf0;
        }
        return key;
    }
}
