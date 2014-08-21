package org.haox.kerb.crypto;

import org.haox.kerb.crypto.enc.EncryptProvider;
import org.haox.kerb.spec.KrbException;

import java.util.Arrays;

public class Cmac {

    private static byte[] constRb = {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, (byte) 0x87
    };

    public static byte[] cmac(EncryptProvider encProvider, byte[] key,
                       byte[] data, int outputSize) throws KrbException {
        return cmac(encProvider, key, data, 0, data.length, outputSize);
    }

    public static byte[] cmac(EncryptProvider encProvider, byte[] key, byte[] data,
                       int start, int len, int outputSize) throws KrbException {
        byte[] hash = Cmac.cmac(encProvider, key, data, start, len);

        byte[] output = new byte[outputSize];
        System.arraycopy(hash, 0, output, 0, outputSize);
        return output;
    }

    public static byte[] cmac(EncryptProvider encProvider,
                              byte[] key, byte[] data) throws KrbException {
        return cmac(encProvider, key, data, 0, data.length);
    }

    public static byte[] cmac(EncryptProvider encProvider,
                              byte[] key, byte[] data, int start, int len) throws KrbException {

        int blockSize = encProvider.blockSize();

        byte[] Y = new byte[blockSize];
        byte[] mLast = new byte[blockSize];
        byte[] padded = new byte[blockSize];
        byte[] K1 = new byte[blockSize];
        byte[] K2 = new byte[blockSize];

        // step 1
        makeSubkey(encProvider, key, K1, K2);

        // step 2
        int n = (len + blockSize - 1) / blockSize;

        // step 3
        boolean lastIsComplete;
        if (n == 0) {
            n = 1;
            lastIsComplete = false;
        } else {
            lastIsComplete = ((len % blockSize) == 0);
        }

        // Step 6 (all but last block)
        byte[] cipherState = new byte[blockSize];
        byte[] cipher = new byte[blockSize];
        for (int i = 0; i < n - 1; i++) {
            System.arraycopy(data, i * blockSize, cipher, 0, blockSize);
            encProvider.encryptBlock(key, cipherState, cipher);
            System.arraycopy(cipher, 0, cipherState, 0, blockSize);
        }

        // step 5
        System.arraycopy(cipher, 0, Y, 0, blockSize);

        // step 4
        int lastPos = (n - 1) * blockSize;
        int lastLen = lastIsComplete ? blockSize : len % blockSize;
        byte[] lastBlock = new byte[lastLen];
        System.arraycopy(data, lastPos, lastBlock, 0, lastLen);
        if (lastIsComplete) {
            xor128(lastBlock, K1, mLast);
        } else {
            padding(lastBlock, padded);
            xor128(padded, K2, mLast);
        }

        // Step 6 (last block)
        encProvider.encryptBlock(key, cipherState, mLast);

        return mLast;
    }

    // Generate subkeys K1 and K2 as described in RFC 4493 figure 2.2.
    private static void makeSubkey(EncryptProvider encProvider,
                              byte[] key, byte[] K1, byte[] K2) throws KrbException {

        // L := encrypt(K, const_Zero)
        byte[] L = new byte[K1.length];
        Arrays.fill(L, (byte) 0);
        encProvider.encryptBlock(key, null, L);

        // K1 := (MSB(L) == 0) ? L << 1 : (L << 1) XOR const_Rb
        if ((L[0] & 0x80) == 0) {
            leftShiftByOne(L, K1);
        } else {
            byte[] tmp = new byte[K1.length];
            leftShiftByOne(L, tmp);
            xor128(tmp, constRb, K1);
        }

        // K2 := (MSB(K1) == 0) ? K1 << 1 : (K1 << 1) XOR const_Rb
        if ((K1[0] & 0x80) == 0) {
            leftShiftByOne(K1, K2);
        } else {
            byte[] tmp = new byte[K1.length];
            leftShiftByOne(K1, tmp);
            xor128(tmp, constRb, K2);
        }
    }

    private static void leftShiftByOne(byte[] input, byte[] output) {
        byte overflow = 0;

        for (int i = input.length - 1; i >= 0; i--) {
            output[i] = (byte) (input[i] << 1);
            output[i] |= overflow;
            overflow = (byte) ((input[i] & 0x80) != 0 ? 1 : 0);
        }
    }

    private static void xor128(byte[] a, byte[] b, byte[] output) {
        int av, bv, v;
        for (int i = 0; i < a.length / 4; ++i) {
            av = bytes2int(a, i * 4);
            bv = bytes2int(b, i * 4);
            v = av ^ bv;
            int2bytes(v, output, i * 4);
        }
    }

    private static int bytes2int(byte[] bytes, int pos) {
        int value = 0;

        for (int i = 0; i < 4; i++) {
            value = (value << 8) + (bytes[pos + i] & 0xff);
        }
        return value;
    }

    private static void int2bytes(int value, byte[] bytes, int pos) {
        for (int i = 0; i < 4; i++) {
            bytes[pos + 3 - i] = (byte)value;
            value >>>= 8;
        }
    }

    // Padding out data with a 1 bit followed by 0 bits, placing the result in pad
    private static void padding(byte[] data, byte[] padded) {
        int len = data.length;

        // original last block
        System.arraycopy(data, 0, padded, 0, len);

        padded[len] = (byte) 0x80;

        for (int i = len + 1; i < padded.length; i++) {
            padded[i] = 0x00;
        }
    }
}
