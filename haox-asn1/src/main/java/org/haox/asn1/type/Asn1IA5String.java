package org.haox.asn1.type;

import org.haox.asn1.BerTag;

public class Asn1IA5String extends Asn1String
{
    public Asn1IA5String() {
        super(BerTag.IA5_STRING);
    }

    public Asn1IA5String(String value) {
        super(value, BerTag.IA5_STRING);
    }
}
