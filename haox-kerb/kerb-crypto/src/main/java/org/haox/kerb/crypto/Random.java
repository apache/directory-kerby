package org.haox.kerb.crypto;

import java.security.SecureRandom;

public final class Random {

    private static SecureRandom srand = new SecureRandom();

    public static byte[] makeBytes(int size) {
        byte[] data = new byte[size];
        srand.nextBytes(data);
        return data;
    }
}
