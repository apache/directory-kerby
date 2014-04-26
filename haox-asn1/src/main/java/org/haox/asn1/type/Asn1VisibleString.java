package org.haox.asn1.type;

import org.haox.asn1.UniversalTag;

public class Asn1VisibleString extends Asn1String
{
    public Asn1VisibleString() {
        this(null);
    }

    public Asn1VisibleString(String value) {
        super(UniversalTag.VISIBLE_STRING, value);
    }
}
