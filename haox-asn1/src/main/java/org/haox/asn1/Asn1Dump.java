package org.haox.asn1;

import org.haox.asn1.type.AbstractAsn1Simple;
import org.haox.asn1.type.Asn1Collection;
import org.haox.asn1.type.Asn1Item;
import org.haox.asn1.type.Asn1Type;

import java.io.IOException;

public class Asn1Dump {
    public static String dump(byte[] content) throws IOException {
        StringBuffer sb = new StringBuffer();

        Asn1InputBuffer buffer = new Asn1InputBuffer(content);
        Asn1Type value;
        while (true) {
            value = buffer.read();
            if (value == null) break;
            dump(value, sb);
        }

        return sb.toString();
    }

    public static String dump(Asn1Type value) {
        StringBuffer sb = new StringBuffer();
        dump(value, sb);
        return sb.toString();
    }

    private static void dump(Asn1Type value, StringBuffer buffer) {
        if (value instanceof AbstractAsn1Simple) {
            buffer.append(((AbstractAsn1Simple) value).getValue().toString());
        } else {
            if (value instanceof Asn1Item) {
                dump(((Asn1Item) value).getValue(), buffer);
            } else if (value instanceof Asn1Collection) {
                for (Asn1Item item : ((Asn1Collection) value).getValue()) {
                    dump(item.getValue(), buffer);
                }
            }
        }
    }
}
