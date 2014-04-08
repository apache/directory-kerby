package org.haox.asn1.type;

public class Asn1UniversalString extends Asn1String
{
    public Asn1UniversalString() {
        super(BerTag.UNIVERSAL_STRING);
    }

    public Asn1UniversalString(String value) {
        super(value, BerTag.UNIVERSAL_STRING);
    }
}
