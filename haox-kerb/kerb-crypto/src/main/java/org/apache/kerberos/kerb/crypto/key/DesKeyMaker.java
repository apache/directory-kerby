package org.apache.kerberos.kerb.crypto.key;

import org.apache.kerberos.kerb.crypto.BytesUtil;
import org.apache.kerberos.kerb.crypto.Des;
import org.apache.kerberos.kerb.crypto.enc.EncryptProvider;
import org.apache.kerberos.kerb.KrbException;

public class DesKeyMaker extends AbstractKeyMaker {

    private static final byte[] goodParity = {
            1,   1,   2,   2,   4,   4,    7,   7,
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

    public DesKeyMaker(EncryptProvider encProvider) {
        super(encProvider);
    }

    @Override
    public byte[] str2key(String string, String salt, byte[] param) throws KrbException {
        char[] passwdSalt = makePasswdSalt(string, salt);
        byte[] key = passwd2key(passwdSalt);
        return key;
    }

    @Override
    public byte[] random2Key(byte[] randomBits) throws KrbException {
        if (randomBits.length != encProvider().keyInputSize()) {
            throw new KrbException("Invalid random bits, not of correct bytes size");
        }

        /**
         * Ref. k5_rand2key_des in random_to_key.c in MIT krb5
         * Take the seven bytes, move them around into the top 7 bits of the
         * 8 key bytes, then compute the parity bits.  Do this three times.
         */
        byte[] key = new byte[encProvider().keySize()];
        int tmp;
        System.arraycopy(randomBits, 0, key, 0, 7);

        key[7] = (byte) (((key[0] & 1) << 1) |
                ((key[1] & 1) << 2) |
                ((key[2] & 1) << 3) |
                ((key[3] & 1) << 4) |
                ((key[4] & 1) << 5) |
                ((key[5] & 1) << 6) |
                ((key[6] & 1) << 7));

        for (int i = 0; i < 8; i++) {
            tmp = key[i] & 0xfe;
            tmp |= (Integer.bitCount(tmp) & 1) ^ 1;
            key[i] = (byte) tmp;
        }

        Des.fixKey(key, 0, 8);

        return key;
    }

    public static final void setParity(byte[] key) {
        for (int i=0; i < 8; i++) {
            key[i] = goodParity[key[i] & 0xff];
        }
    }

    private long passwd2long(byte[] passwdBytes) {
        int keySize = 8;

        long lKey = 0;
        int n = passwdBytes.length / keySize;
        long l, l1, l2 = 0;
        for (int i = 0; i < n; i++) {
            l = BytesUtil.bytes2long(passwdBytes,
                    i * keySize, true) & 0x7f7f7f7f7f7f7f7fL;
            if (i % 2 == 1) {
                l1 = 0;
                for (int j = 0; j < 64; j++) {
                    l1 |= ((l & (1L << j)) >>> j) << (63 - j);
                }
                l = l1 >>> 1;
            }
            lKey ^= (l << 1);
        }

        return lKey;
    }

    private byte[] passwd2key(char[] passwdChars) throws KrbException {
        int keySize = 8;

        byte[] bytes = (new String(passwdChars)).getBytes();
        byte[] passwdBytes = BytesUtil.padding(bytes, keySize);
        long lKey = passwd2long(passwdBytes);

        byte[] keyBytes = BytesUtil.long2bytes(lKey, true);
        fixKey(keyBytes);

        byte[] iv = keyBytes;
        byte[] encKey = keyBytes;

        byte[] bKey = null;
        if (encProvider().supportCbcMac()) {
            bKey = encProvider().cbcMac(iv, encKey, passwdBytes);
        } else {
            throw new KrbException("cbcMac should be supported by the provider: "
                    + encProvider().getClass());
        }

        fixKey(bKey);

        return bKey;
    }

    private void fixKey(byte[] key) {
        setParity(key);
        if (Des.isWeakKey(key, 0, key.length)) {
            Des.fixKey(key, 0, key.length);
        }
    }
}
