package org.haox.util;

public class HexUtil {

    final static String HEX_CHARS_STR = "0123456789ABCDEF";
    final static char[] HEX_CHARS = HEX_CHARS_STR.toCharArray();

    /**
     * Convert bytes into format as:
     * 02020080
     */
    public static String bytesToHex(byte[] bytes) {
        int len = bytes.length * 2;
        char[] hexChars = new char[len];
        for ( int j = 0; j < bytes.length; j++ ) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_CHARS[v >>> 4];
            hexChars[j * 2 + 1] = HEX_CHARS[v & 0x0F];
        }

        return new String(hexChars);
    }

    /**
     * Convert hex string like follows into byte array
     * 02020080
     */
    public static byte[] hex2bytes(String hexString) {
        hexString = hexString.toUpperCase();
        int len = hexString.length() / 2;
        byte[] bytes = new byte[len];
        char[] hexChars = hexString.toCharArray();
        for (int i = 0, j = 0; i < len; ++i) {
            bytes[i] = (byte) ((HEX_CHARS_STR.indexOf(hexChars[j++]) << 4) + HEX_CHARS_STR.indexOf(hexChars[j++]));
        }

        return bytes;
    }
}
