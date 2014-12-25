package org.apache.kerberos.kerb.crypto;

import java.security.SecureRandom;

public class Nonce {

    private static SecureRandom srand = new SecureRandom();

    public static synchronized int value() {
        int value = srand.nextInt();
        return value & 0x7fffffff;
    }
}
