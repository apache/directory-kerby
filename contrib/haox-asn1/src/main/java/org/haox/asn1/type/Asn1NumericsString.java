package org.haox.asn1.type;

import org.haox.asn1.UniversalTag;

public class Asn1NumericsString extends Asn1String
{
    public Asn1NumericsString() {
        this(null);
    }

    public Asn1NumericsString(String value) {
        super(UniversalTag.NUMERIC_STRING, value);
        if (value != null) {
            if (!isNumeric(value)) {
                throw new IllegalArgumentException("Invalid numeric string");
            }
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
