package org.haox.asn1.type;

import org.haox.asn1.BerTag;

public class Asn1PrintableString extends Asn1String
{
    public Asn1PrintableString() {
        super(BerTag.PRINTABLE_STRING);
    }

    public Asn1PrintableString(String value) {
        super(value, BerTag.PRINTABLE_STRING);
    }
}
