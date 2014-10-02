package org.haox.kerb.crypto;

public class BytesUtil {

    public static short bytes2Short(byte[] bytes, boolean bigEndian) {
        short val = 0;

        if (bigEndian) {
            val += (bytes[0] & 0xff) << 8;
            val += (bytes[1] & 0xff);
        } else {
            val += (bytes[1] & 0xff) << 8;
            val += (bytes[0] & 0xff);
        }

        return val;
    }

    public static byte[] short2bytesBe(int val, boolean bigEndian) {
        byte[] bytes = new byte[2];

        if (bigEndian) {
            bytes[0] = (byte) ((val >> 8) & 0xff);
            bytes[1] = (byte) ((val) & 0xff);
        } else {
            bytes[1] = (byte) ((val >>  8) & 0xff);
            bytes[0] = (byte) ((val      ) & 0xff);
        }

        return bytes;
    }

    public static int bytes2int(byte[] bytes, boolean bigEndian) {
        return bytes2int(bytes, 0, bigEndian);
    }

    public static int bytes2int(byte[] bytes, int offset, boolean bigEndian) {
        int val = 0;

        if (bigEndian) {
            val += (bytes[offset + 0] & 0xff) << 24;
            val += (bytes[offset + 1] & 0xff) << 16;
            val += (bytes[offset + 2] & 0xff) << 8;
            val += (bytes[offset + 3] & 0xff);
        } else {
            val += (bytes[offset + 3] & 0xff) << 24;
            val += (bytes[offset + 2] & 0xff) << 16;
            val += (bytes[offset + 1] & 0xff) << 8;
            val += (bytes[offset + 0] & 0xff);
        }

        return val;
    }

    public static byte[] int2bytes(int val, boolean bigEndian) {
        byte[] bytes = new byte[4];

        int2bytes(val, bytes, 0, bigEndian);

        return bytes;
    }

    public static void int2bytes(int val, byte[] bytes, int offset, boolean bigEndian) {
        if (bigEndian) {
            bytes[offset + 0] = (byte) ((val >> 24) & 0xff);
            bytes[offset + 1] = (byte) ((val >> 16) & 0xff);
            bytes[offset + 2] = (byte) ((val >> 8) & 0xff);
            bytes[offset + 3] = (byte) ((val) & 0xff);
        } else {
            bytes[offset + 3] = (byte) ((val >> 24) & 0xff);
            bytes[offset + 2] = (byte) ((val >> 16) & 0xff);
            bytes[offset + 1] = (byte) ((val >> 8) & 0xff);
            bytes[offset + 0] = (byte) ((val) & 0xff);
        }
    }

    public static byte[] long2bytes(long val, boolean bigEndian) {
        byte[] bytes = new byte[8];
        long2bytes(val, bytes, 0, bigEndian);
        return bytes;
    }

    public static void long2bytes(long val, byte[] bytes, int offset, boolean bigEndian) {
        if (bigEndian) {
            for (int i = 0; i < 8; i++) {
                bytes[i + offset] = (byte) ((val >> ((7 - i) * 8)) & 0xffL);
            }
        } else {
            for (int i = 0; i < 8; i++) {
                bytes[i + offset] = (byte) ((val >> (i * 8)) & 0xffL);
            }
        }
    }

    public static long bytes2long(byte[] bytes, boolean bigEndian) {
        return bytes2long(bytes, 0, bigEndian);
    }

    public static long bytes2long(byte[] bytes, int offset, boolean bigEndian) {
        long val = 0;

        if (bigEndian) {
            for (int i = 0; i < 8; i++) {
                val |= (((long) bytes[i + offset]) & 0xffL) << ((7 - i) * 8);
            }
        } else {
            for (int i = 0; i < 8; i++) {
                val |= (((long) bytes[i + offset]) & 0xffL) << (i * 8);
            }
        }

        return val;
    }

    public static byte[] padding(byte[] data, int block) {
        int len = data.length;
        int paddingLen = len % block != 0 ? 8 - len % block : 0;
        if (paddingLen == 0) {
            return data;
        }

        byte[] result = new byte[len + + paddingLen];
        System.arraycopy(data, 0, result, 0, len);
        return result;
    }

    public static byte[] duplicate(byte[] bytes) {
        byte[] dup = new byte[bytes.length];
        System.arraycopy(bytes, 0, dup, 0, bytes.length);
        return dup;
    }
}
