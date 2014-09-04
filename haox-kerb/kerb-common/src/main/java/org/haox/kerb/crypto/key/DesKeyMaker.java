package org.haox.kerb.crypto.key;

import org.haox.kerb.crypto.Util;
import org.haox.kerb.crypto.enc.EncryptProvider;
import org.haox.kerb.spec.KrbException;

import java.util.Arrays;

public class DesKeyMaker extends AbstractKeyMaker {

    private static final long[] badKeys = {
            0x0101010101010101L, 0xfefefefefefefefeL,
            0x1f1f1f1f1f1f1f1fL, 0xe0e0e0e0e0e0e0e0L,
            0x01fe01fe01fe01feL, 0xfe01fe01fe01fe01L,
            0x1fe01fe00ef10ef1L, 0xe01fe01ff10ef10eL,
            0x01e001e001f101f1L, 0xe001e001f101f101L,
            0x1ffe1ffe0efe0efeL, 0xfe1ffe1ffe0efe0eL,
            0x011f011f010e010eL, 0x1f011f010e010e01L,
            0xe0fee0fef1fef1feL, 0xfee0fee0fef1fef1L
    };

    private static final byte[] goodParity = {
            1,       1,   2,   2,   4,   4,   7,   7,
            8,   8,   11,  11,  13,  13,  14,  14,
            16,  16,  19,  19,  21,  21,  22,  22,
            25,  25,  26,  26,  28,  28,  31,  31,
            32,  32,  35,  35,  37,  37,  38,  38,
            41,  41,  42,  42,  44,  44,  47,  47,
            49,  49,  50,  50,  52,  52,  55,  55,
            56,  56,  59,  59,  61,  61,  62,  62,
            64,  64,  67,  67,  69,  69,  70,  70,
            73,  73,  74,  74,  76,  76,  79,  79,
            81,  81,  82,  82,  84,  84,  87,  87,
            88,  88,  91,  91,  93,  93,  94,  94,
            97,  97,  98,  98,  100, 100, 103, 103,
            104, 104, 107, 107, 109, 109, 110, 110,
            112, 112, 115, 115, 117, 117, 118, 118,
            121, 121, 122, 122, 124, 124, 127, 127,
            (byte)128, (byte)128, (byte)131, (byte)131,
            (byte)133, (byte)133, (byte)134, (byte)134,
            (byte)137, (byte)137, (byte)138, (byte)138,
            (byte)140, (byte)140, (byte)143, (byte)143,
            (byte)145, (byte)145, (byte)146, (byte)146,
            (byte)148, (byte)148, (byte)151, (byte)151,
            (byte)152, (byte)152, (byte)155, (byte)155,
            (byte)157, (byte)157, (byte)158, (byte)158,
            (byte)161, (byte)161, (byte)162, (byte)162,
            (byte)164, (byte)164, (byte)167, (byte)167,
            (byte)168, (byte)168, (byte)171, (byte)171,
            (byte)173, (byte)173, (byte)174, (byte)174,
            (byte)176, (byte)176, (byte)179, (byte)179,
            (byte)181, (byte)181, (byte)182, (byte)182,
            (byte)185, (byte)185, (byte)186, (byte)186,
            (byte)188, (byte)188, (byte)191, (byte)191,
            (byte)193, (byte)193, (byte)194, (byte)194,
            (byte)196, (byte)196, (byte)199, (byte)199,
            (byte)200, (byte)200, (byte)203, (byte)203,
            (byte)205, (byte)205, (byte)206, (byte)206,
            (byte)208, (byte)208, (byte)211, (byte)211,
            (byte)213, (byte)213, (byte)214, (byte)214,
            (byte)217, (byte)217, (byte)218, (byte)218,
            (byte)220, (byte)220, (byte)223, (byte)223,
            (byte)224, (byte)224, (byte)227, (byte)227,
            (byte)229, (byte)229, (byte)230, (byte)230,
            (byte)233, (byte)233, (byte)234, (byte)234,
            (byte)236, (byte)236, (byte)239, (byte)239,
            (byte)241, (byte)241, (byte)242, (byte)242,
            (byte)244, (byte)244, (byte)247, (byte)247,
            (byte)248, (byte)248, (byte)251, (byte)251,
            (byte)253, (byte)253, (byte)254, (byte)254
    };

    public static final byte[] setParity(byte[] key) {
        for (int i=0; i < 8; i++) {
            key[i] = goodParity[key[i] & 0xff];
        }
        return key;
    }

    public static final long setParity(long key) {
        return Util.bytes2long(setParity(Util.long2bytes(key)));
    }

    public static final boolean isBadKey(long key) {
        for (int i = 0; i < badKeys.length; i++) {
            if (badKeys[i] == key) {
                return true;
            }
        }
        return false;
    }

    public static final boolean isBadKey(byte[] key) {
        return isBadKey(Util.bytes2long(key, 0));
    }

    public long passwd2long(char[] passwdChars) throws KrbException {
        long key = 0;
        long octet, octet1, octet2 = 0;
        byte[] cbytes = null;

        // Convert password to byte array
        cbytes = (new String(passwdChars)).getBytes();

        // pad data
        byte[] passwdBytes = pad(cbytes);

        byte[] newkey = new byte[8];
        int length = (passwdBytes.length / 8) + (passwdBytes.length % 8  == 0 ? 0 : 1);
        for (int i = 0; i < length; i++) {
            octet = Util.bytes2long(passwdBytes, i * 8) & 0x7f7f7f7f7f7f7f7fL;
            if (i % 2 == 1) {
                octet1 = 0;
                for (int j = 0; j < 64; j++) {
                    octet1 |= ((octet & (1L << j)) >>> j) << (63 - j);
                }
                octet = octet1 >>> 1;
            }
            key ^= (octet << 1);
        }
        key = setParity(key);
        if (isBadKey(key)) {
            byte [] temp = Util.long2bytes(key);
            temp[7] ^= 0xf0;
            key = Util.bytes2long(temp);
        }

        byte[] iv = Util.long2bytes(key);
        byte[] encKey = Util.long2bytes(key);

        if (encProvider().supportCbcMac()) {
            newkey = encProvider().cbcMac(iv, encKey, passwdBytes);
        } else {
            throw new KrbException("cbcMac should be supported by the provider: " + encProvider().getClass());
        }

        key = Util.bytes2long(setParity(newkey));
        if (isBadKey(key)) {
            byte [] temp = Util.long2bytes(key);
            temp[7] ^= 0xf0;
            key = Util.bytes2long(temp);
        }

        // clear-up sensitive information
        if (cbytes != null) {
            Arrays.fill(cbytes, 0, cbytes.length, (byte) 0);
        }
        if (passwdBytes != null) {
            Arrays.fill(passwdBytes, 0, passwdBytes.length, (byte) 0);
        }

        return key;
    }

    static byte[] pad(byte[] data) {
        int len;
        if (data.length < 8) len = data.length;
        else len = data.length % 8;
        if (len == 0) return data;
        else {
            byte[] padding = new byte[ 8 - len + data.length];
            for (int i = padding.length - 1; i > data.length - 1; i--) {
                padding[i] = 0;
            }
            System.arraycopy(data, 0, padding, 0, data.length);
            return padding;
        }
    }

    public DesKeyMaker(EncryptProvider encProvider) {
        super(encProvider);
    }

    @Override
    public byte[] str2key(String string, String salt, byte[] param) throws KrbException {
        String error = null;
        int type = 0;

        if (param != null) {
            if (param.length != 1) {
                error = "Invalid param to S2K";
            }
            type = param[0];
            if (type != 0 && type != 1) {
                error = "Invalid param to S2K";
            }
        }
        if (type == 1) {
            error = "AFS not supported yet";
        }

        if (error != null) {
            throw new KrbException(error);
        }

        char[] passwdSalt = makePasswdSalt(string, salt);
        long keyLong = passwd2long(passwdSalt);
        return Util.long2bytes(keyLong);
    }

    @Override
    public byte[] random2Key(byte[] randomBits) throws KrbException {
        return randomBits;
    }
}
