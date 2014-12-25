package org.apache.haox.asn1.type;

import org.apache.haox.asn1.UniversalTag;

public class Asn1T61String extends Asn1String
{
    public Asn1T61String() {
        this(null);
    }

    public Asn1T61String(String value) {
        super(UniversalTag.T61_STRING, value);
    }
}
