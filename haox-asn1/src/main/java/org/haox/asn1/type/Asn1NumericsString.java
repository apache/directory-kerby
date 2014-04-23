package org.haox.asn1.type;

import org.haox.asn1.BerTag;

public class Asn1NumericsString extends Asn1String
{
    public Asn1NumericsString() {
        super(BerTag.NUMERIC_STRING);
    }

    public Asn1NumericsString(String value) {
        super(value, BerTag.NUMERIC_STRING);
        if (!isNumeric(value)) {
            throw new IllegalArgumentException("Invalid numeric string");
        }
    }

    public static boolean isNumeric(String  s) {
        char c;
        for (int i = s.length() - 1; i >= 0; i--) {
            c = s.charAt(i);
            if ((c >= '0' && c <= '9') || c == ' ') {
                continue;
            }
            return false;
        }
        return true;
    }
}
