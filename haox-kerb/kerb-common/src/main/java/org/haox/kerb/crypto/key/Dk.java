package org.haox.kerb.crypto.key;

import java.util.Arrays;

public class Dk {

    public static byte[] nfold(byte[] input, int size) {

        int inbits = input.length;

        /* first compute lcm(n,k) */
        int a, b, c, lcm;
        a = size;  // n
        b = inbits;   // k

        while (b != 0) {
            c = b;
            b = a % b;
            a = c;
        }
        lcm = size*inbits/a;

        /* now do the real work */
        byte[] out = new byte[size];
        Arrays.fill(out, (byte)0);

        int thisbyte = 0;
        int msbit, i, bval, oval;

        // this will end up cycling through k lcm(k,n)/k times, which
        // is correct
        for (i = lcm-1; i >= 0; i--) {
            /* compute the msbit input k which gets added into this byte */
            msbit = (/* first, start with msbit input the first, unrotated byte */
                ((inbits<<3)-1)
                /* then, for each byte, shift to right for each repetition */
                + (((inbits<<3)+13)*(i/inbits))
                /* last, pick out correct byte within that shifted repetition */
                + ((inbits-(i%inbits)) << 3)) % (inbits << 3);

            /* pull out the byte value itself */
            // Mask off values using &0xff to get only the lower byte
            // Use >>> to avoid sign extension
            bval =  ((((input[((inbits-1)-(msbit>>>3))%inbits]&0xff)<<8)|
                (input[((inbits)-(msbit>>>3))%inbits]&0xff))
                >>>((msbit&7)+1))&0xff;

            /*
            System.err.println("((" +
                ((input[((inbits-1)-(msbit>>>3))%inbits]&0xff)<<8)
                + "|" + (input[((inbits)-(msbit>>>3))%inbits]&0xff) + ")"
                + ">>>" + ((msbit&7)+1) + ")&0xff = " + bval);
            */

            thisbyte += bval;

            /* do the addition */
            // Mask off values using &0xff to get only the lower byte
            oval = (out[i%size]&0xff);
            thisbyte += oval;
            out[i%size] = (byte) (thisbyte&0xff);

            /* keep around the carry bit, if any */
            thisbyte >>>= 8;
        }

        /* if there's a carry bit left over, add it back input */
        if (thisbyte != 0) {
            for (i = size-1; i >= 0; i--) {
                /* do the addition */
                thisbyte += (out[i]&0xff);
                out[i] = (byte) (thisbyte&0xff);

                /* keep around the carry bit, if any */
                thisbyte >>>= 8;
            }
        }

        return out;
    }
}
