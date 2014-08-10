package org.haox.kerb.crypto.key;

import org.haox.kerb.crypto.EncTypeHandler;
import org.haox.kerb.crypto.enc.EncryptProvider;
import org.haox.kerb.spec.KrbException;

import javax.crypto.spec.DESKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;

public class Des3KeyMaker extends AbstractKeyMaker {

    public Des3KeyMaker(EncryptProvider encProvider) {
        super(encProvider);
    }

    @Override
    public byte[] str2key(String string, String salt, byte[] param) throws KrbException {
        char[] passwdSalt = makePasswdSalt(string, salt);
        int keyInputSize = encProvider().keyInputSize();
        try {
            byte[] utf8Bytes = new String(passwdSalt).getBytes("UTF-8");
            byte[] tmpKey = random2Key(Dk.nfold(utf8Bytes, keyInputSize));
            return dk(tmpKey, KERBEROS_CONSTANT);
        } catch (UnsupportedEncodingException e) {
            throw new KrbException("str2key failed", e);
        }
    }

    /*
     * The 168 bits of random key data are converted to a protocol key value
     * as follows.  First, the 168 bits are divided into three groups of 56
     * bits, which are expanded individually into 64 bits as in des3Expand().
     * Result is a 24 byte (192-bit) key.
     */
    @Override
    public byte[] random2Key(byte[] randomBits) throws KrbException {
        byte[] one = keyCorrection(des3Expand(randomBits, 0, 7));
        byte[] two = keyCorrection(des3Expand(randomBits, 7, 14));
        byte[] three = keyCorrection(des3Expand(randomBits, 14, 21));

        byte[] key = new byte[24];
        System.arraycopy(one, 0, key, 0, 8);
        System.arraycopy(two, 0, key, 8, 8);
        System.arraycopy(three, 0, key, 16, 8);

        return key;
    }

    private static byte[] keyCorrection(byte[] key) {
        // check for weak key
        try {
            if (DESKeySpec.isWeak(key, 0)) {
                key[7] = (byte)(key[7] ^ 0xF0);
            }
        } catch (InvalidKeyException ex) {
            // swallow, since it should never happen
        }
        return key;
    }

    /**
     * Expands a 7-byte array into an 8-byte array that contains parity bits.
     * The 56 bits are expanded into 64 bits as follows:
     *   1  2  3  4  5  6  7  p
     *   9 10 11 12 13 14 15  p
     *   17 18 19 20 21 22 23  p
     *   25 26 27 28 29 30 31  p
     *   33 34 35 36 37 38 39  p
     *   41 42 43 44 45 46 47  p
     *   49 50 51 52 53 54 55  p
     *   56 48 40 32 24 16  8  p
     *
     * (PI,P2,...,P8) are reserved for parity bits computed on the preceding
     * seven independent bits and set so that the parity of the octet is odd,
     * i.e., there is an odd number of "1" bits in the octet.
     */
    private static byte[] des3Expand(byte[] input, int start, int end) {
        if ((end - start) != 7)
            throw new IllegalArgumentException(
                    "Invalid length of DES Key Value:" + start + "," + end);

        byte[] result = new byte[8];
        byte last = 0;
        System.arraycopy(input, start, result, 0, 7);
        byte posn = 0;

        // Fill in last row
        for (int i = start; i < end; i++) {
            byte bit = (byte) (input[i]&0x01);

            ++posn;
            if (bit != 0) {
                last |= (bit<<posn);
            }
        }

        result[7] = last;
        setParityBit(result);
        return result;
    }

    /**
     * Sets the parity bit (0th bit) in each byte so that each byte
     * contains an odd number of 1's.
     */
    private static void setParityBit(byte[] key) {
        for (int i = 0; i < key.length; i++) {
            int b = key[i] & 0xfe;
            b |= (Integer.bitCount(b) & 1) ^ 1;
            key[i] = (byte) b;
        }
    }
}
