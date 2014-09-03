package org.haox.kerb.crypto;

public class Util {

    public static byte[] duplicate(byte[] bytes) {
        byte[] dup = new byte[bytes.length];
        System.arraycopy(bytes, 0, dup, 0, bytes.length);
        return dup;
    }

    public static int bytes2intBe(byte[] bytes, int offset) {
        int val = 0;

        val += bytes[offset + 0] << 24;
        val += bytes[offset + 1] << 16;
        val += bytes[offset + 2] << 8;
        val += bytes[offset + 3] & 0xff;

        return val;
    }

    public static void int2bytesBe(int val, byte[] bytes, int offset) {
        bytes[offset + 0] = (byte) ((val >> 24) & 0xff);
        bytes[offset + 1] = (byte) ((val >> 16) & 0xff);
        bytes[offset + 2] = (byte) ((val >>  8) & 0xff);
        bytes[offset + 3] = (byte) ((val      ) & 0xff);
    }

    public static int bytes2intLe(byte[] bytes, int offset) {
        int val = (bytes[0] | (bytes[1] << 8) | (bytes[2] << 16) | (bytes[3] << 24));
        return val;
    }

    public static void int2bytesLe(int val, byte[] bytes, int offset) {
        bytes[offset + 3] = (byte) ((val >> 24) & 0xff);
        bytes[offset + 2] = (byte) ((val >> 16) & 0xff);
        bytes[offset + 1] = (byte) ((val >>  8) & 0xff);
        bytes[offset + 0] = (byte) ((val      ) & 0xff);
    }
}
