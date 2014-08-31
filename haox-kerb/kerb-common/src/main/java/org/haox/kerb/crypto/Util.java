package org.haox.kerb.crypto;

public class Util {

    public static int bytes2intBe(byte[] bytes, int pos) {
        int val = 0;

        val += bytes[pos + 0] << 24;
        val += bytes[pos + 1] << 16;
        val += bytes[pos + 2] << 8;
        val += bytes[pos + 3] & 0xff;

        return val;
    }

    public static void int2bytesBe(int val, byte[] bytes, int pos) {
        bytes[pos + 0] = (byte) ((val >> 24) & 0xff);
        bytes[pos + 1] = (byte) ((val >> 16) & 0xff);
        bytes[pos + 2] = (byte) ((val >>  8) & 0xff);
        bytes[pos + 3] = (byte) ((val      ) & 0xff);
    }
}
