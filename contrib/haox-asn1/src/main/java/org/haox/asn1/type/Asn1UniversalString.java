package org.haox.asn1.type;

import org.haox.asn1.UniversalTag;

public class Asn1UniversalString extends Asn1String
{
    public Asn1UniversalString() {
        this(null);
    }

    public Asn1UniversalString(String value) {
        super(UniversalTag.UNIVERSAL_STRING, value);
    }
}
