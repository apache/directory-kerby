package org.haox.asn1.type;

import org.haox.asn1.BerTag;

public class Asn1VisibleString extends Asn1String
{
    public Asn1VisibleString() {
        super(BerTag.VISIBLE_STRING);
    }

    public Asn1VisibleString(String value) {
        super(value, BerTag.VISIBLE_STRING);
    }
}
