package org.haox.asn1.type;

import org.haox.asn1.BerTag;

public class Asn1GeneralString extends Asn1String
{
    public Asn1GeneralString() {
        super(BerTag.GENERAL_STRING);
    }

    public Asn1GeneralString(String value) {
        super(value, BerTag.GENERAL_STRING);
    }
}
