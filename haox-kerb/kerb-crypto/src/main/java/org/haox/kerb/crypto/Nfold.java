package org.haox.kerb.crypto;

import java.util.Arrays;

public class Nfold {

    public static byte[] nfold(byte[] input, int size) {

        int inbits = input.length;

        int a, b, c, lcm;
        a = size;
        b = inbits;

        while (b != 0) {
            c = b;
            b = a % b;
            a = c;
        }
        lcm = size*inbits/a;

        byte[] out = new byte[size];
        Arrays.fill(out, (byte)0);

        int thisbyte = 0;
        int msbit, i, bval, oval;

        for (i = lcm-1; i >= 0; i--) {
            msbit = (
                ((inbits<<3)-1)
                + (((inbits<<3)+13)*(i/inbits))
                + ((inbits-(i%inbits)) << 3)) % (inbits << 3);

            bval =  ((((input[((inbits-1)-(msbit>>>3))%inbits]&0xff)<<8)|
                (input[((inbits)-(msbit>>>3))%inbits]&0xff))
                >>>((msbit&7)+1))&0xff;

            thisbyte += bval;
            oval = (out[i%size]&0xff);
            thisbyte += oval;
            out[i%size] = (byte) (thisbyte&0xff);

            thisbyte >>>= 8;
        }

        if (thisbyte != 0) {
            for (i = size-1; i >= 0; i--) {
                thisbyte += (out[i]&0xff);
                out[i] = (byte) (thisbyte&0xff);

                thisbyte >>>= 8;
            }
        }

        return out;
    }
}
