package org.apache.commons.ssl.util;

import java.io.UnsupportedEncodingException;

public class UTF8 {

    public static String toString(byte[] bytes) {
        try {
            return new String(bytes, "UTF-8");
        } catch (UnsupportedEncodingException uee) {
            throw new RuntimeException("UTF8 unavailable", uee);
        }
    }

    public static byte[] toBytes(String s) {
        try {
            return s.getBytes("UTF-8");
        } catch (UnsupportedEncodingException uee) {
            throw new RuntimeException("UTF8 unavailable", uee);
        }
    }
}
