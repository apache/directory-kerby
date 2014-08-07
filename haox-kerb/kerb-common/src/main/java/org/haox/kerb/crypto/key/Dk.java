package org.haox.kerb.crypto.key;

import org.haox.kerb.crypto.Confounder;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.common.KeyUsage;

import javax.crypto.Cipher;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
import java.util.Arrays;

public class Dk {

    public static byte[] nfold(byte[] in, int outbits) {

        int inbits = in.length;
        outbits >>= 3;    // count in bytes

        /* first compute lcm(n,k) */
        int a, b, c, lcm;
        a = outbits;  // n
        b = inbits;   // k

        while (b != 0) {
            c = b;
            b = a % b;
            a = c;
        }
        lcm = outbits*inbits/a;

        /* now do the real work */
        byte[] out = new byte[outbits];
        Arrays.fill(out, (byte)0);

        int thisbyte = 0;
        int msbit, i, bval, oval;

        // this will end up cycling through k lcm(k,n)/k times, which
        // is correct
        for (i = lcm-1; i >= 0; i--) {
            /* compute the msbit in k which gets added into this byte */
            msbit = (/* first, start with msbit in the first, unrotated byte */
                ((inbits<<3)-1)
                /* then, for each byte, shift to right for each repetition */
                + (((inbits<<3)+13)*(i/inbits))
                /* last, pick out correct byte within that shifted repetition */
                + ((inbits-(i%inbits)) << 3)) % (inbits << 3);

            /* pull out the byte value itself */
            // Mask off values using &0xff to get only the lower byte
            // Use >>> to avoid sign extension
            bval =  ((((in[((inbits-1)-(msbit>>>3))%inbits]&0xff)<<8)|
                (in[((inbits)-(msbit>>>3))%inbits]&0xff))
                >>>((msbit&7)+1))&0xff;

            /*
            System.err.println("((" +
                ((in[((inbits-1)-(msbit>>>3))%inbits]&0xff)<<8)
                + "|" + (in[((inbits)-(msbit>>>3))%inbits]&0xff) + ")"
                + ">>>" + ((msbit&7)+1) + ")&0xff = " + bval);
            */

            thisbyte += bval;

            /* do the addition */
            // Mask off values using &0xff to get only the lower byte
            oval = (out[i%outbits]&0xff);
            thisbyte += oval;
            out[i%outbits] = (byte) (thisbyte&0xff);

            /* keep around the carry bit, if any */
            thisbyte >>>= 8;
        }

        /* if there's a carry bit left over, add it back in */
        if (thisbyte != 0) {
            for (i = outbits-1; i >= 0; i--) {
                /* do the addition */
                thisbyte += (out[i]&0xff);
                out[i] = (byte) (thisbyte&0xff);

                /* keep around the carry bit, if any */
                thisbyte >>>= 8;
            }
        }

        return out;
    }

    // Routines used for debugging
    static String bytesToString(byte[] digest) {
        // Get character representation of digest
        StringBuffer digestString = new StringBuffer();

        for (int i = 0; i < digest.length; i++) {
            if ((digest[i] & 0x000000ff) < 0x10) {
                digestString.append("0" +
                    Integer.toHexString(digest[i] & 0x000000ff));
            } else {
                digestString.append(
                    Integer.toHexString(digest[i] & 0x000000ff));
            }
        }
        return digestString.toString();
    }

    private static byte[] binaryStringToBytes(String str) {
        char[] usageStr = str.toCharArray();
        byte[] usage = new byte[usageStr.length/2];
        for (int i = 0; i < usage.length; i++) {
            byte a = Byte.parseByte(new String(usageStr, i*2, 1), 16);
            byte b = Byte.parseByte(new String(usageStr, i*2 + 1, 1), 16);
            usage[i] = (byte) ((a<<4)|b);
        }
        return usage;
    }

// String.getBytes("UTF-8");
// Do this instead of using String to avoid making password immutable
    static byte[] charToUtf8(char[] chars) {
        Charset utf8 = Charset.forName("UTF-8");

        CharBuffer cb = CharBuffer.wrap(chars);
        ByteBuffer bb = utf8.encode(cb);
        int len = bb.limit();
        byte[] answer = new byte[len];
        bb.get(answer, 0, len);
        return answer;
    }

    static byte[] charToUtf16(char[] chars) {
        Charset utf8 = Charset.forName("UTF-16LE");

        CharBuffer cb = CharBuffer.wrap(chars);
        ByteBuffer bb = utf8.encode(cb);
        int len = bb.limit();
        byte[] answer = new byte[len];
        bb.get(answer, 0, len);
        return answer;
    }
}
