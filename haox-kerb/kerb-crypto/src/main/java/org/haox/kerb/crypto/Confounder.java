package org.haox.kerb.crypto;

import java.security.SecureRandom;

public final class Confounder {
    private static SecureRandom srand = new SecureRandom();

    private Confounder() { // not instantiable
    }

    public static byte[] bytes(int size) {
        byte[] data = new byte[size];
        srand.nextBytes(data);
        return data;
    }

    public static int intValue() {
        return srand.nextInt();
    }

    public static long longValue() {
        return srand.nextLong();
    }
}
