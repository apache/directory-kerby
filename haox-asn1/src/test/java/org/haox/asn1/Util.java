package org.haox.asn1;

public class Util {

    final static char[] hexArray = "0123456789ABCDEF".toCharArray();
    public static String bytesToHex(byte[] bytes) {
        int len = bytes.length * 2;
        len += bytes.length; // for ','
        char[] hexChars = new char[len];
        for ( int j = 0; j < bytes.length; j++ ) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 3] = hexArray[v >>> 4];
            hexChars[j * 3 + 1] = hexArray[v & 0x0F];
            hexChars[j * 3 + 2] = ',';
        }

        return new String(hexChars);
    }

}
