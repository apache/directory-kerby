package org.apache.haox.asn1.type;

import org.apache.haox.asn1.UniversalTag;

public class Asn1GeneralString extends Asn1String
{
    public Asn1GeneralString() {
        super(UniversalTag.GENERAL_STRING);
    }

    public Asn1GeneralString(String value) {
        super(UniversalTag.GENERAL_STRING, value);
    }
}
