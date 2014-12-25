package org.apache.haox.asn1.type;

import org.apache.haox.asn1.UniversalTag;

public class Asn1IA5String extends Asn1String
{
    public Asn1IA5String() {
        super(UniversalTag.IA5_STRING);
    }

    public Asn1IA5String(String value) {
        super(UniversalTag.IA5_STRING, value);
    }
}
