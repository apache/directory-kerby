package org.apache.kerberos.kerb.crypto;

public class Util {

    public static void xor(byte[] input, int offset, byte[] output) {
        int a, b;
        for (int i = 0; i < output.length / 4; ++i) {
            a = BytesUtil.bytes2int(input, offset + i * 4, true);
            b = BytesUtil.bytes2int(output, i * 4, true);
            b = a ^ b;
            BytesUtil.int2bytes(b, output, i * 4, true);
        }
    }

    public static void xor(byte[] a, byte[] b, byte[] output) {
        int av, bv, v;
        for (int i = 0; i < a.length / 4; ++i) {
            av = BytesUtil.bytes2int(a, i * 4, true);
            bv = BytesUtil.bytes2int(b, i * 4, true);
            v = av ^ bv;
            BytesUtil.int2bytes(v, output, i * 4, true);
        }
    }
}
