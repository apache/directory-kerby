package org.apache.haox.asn1.type;

import org.apache.haox.asn1.UniversalTag;

public class Asn1PrintableString extends Asn1String
{
    public Asn1PrintableString() {
        this(null);
    }

    public Asn1PrintableString(String value) {
        super(UniversalTag.PRINTABLE_STRING, value);
    }
}
