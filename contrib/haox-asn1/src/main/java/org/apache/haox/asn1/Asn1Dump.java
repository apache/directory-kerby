package org.apache.haox.asn1;

import org.apache.haox.asn1.type.Asn1Item;
import org.apache.haox.asn1.type.Asn1Simple;
import org.apache.haox.asn1.type.Asn1Type;

import java.io.IOException;

public class Asn1Dump {

    public static void dump(byte[] content) throws IOException {
        String dumped = dumpAsString(content);
        System.out.println(dumped);
    }

    public static String dumpAsString(byte[] content) throws IOException {
        StringBuilder sb = new StringBuilder();

        Asn1InputBuffer buffer = new Asn1InputBuffer(content);
        Asn1Type value;
        while (true) {
            value = buffer.read();
            if (value == null) break;
            dump(value, sb);
        }

        return sb.toString();
    }

    public static String dumpAsString(Asn1Type value) {
        StringBuilder sb = new StringBuilder();
        dump(value, sb);
        return sb.toString();
    }

    private static void dump(Asn1Type value, StringBuilder buffer) {
        if (value instanceof Asn1Simple) {
            buffer.append(((Asn1Simple) value).getValue().toString());
        } else if (value instanceof Asn1Item) {
            dump((Asn1Item) value, buffer);
        }
    }

    private static void dump(Asn1Item value, StringBuilder buffer) {
        if (value.isFullyDecoded()) {
            dump(value.getValue(), buffer);
        } else {
            buffer.append("Asn1Item");
        }
    }
}
