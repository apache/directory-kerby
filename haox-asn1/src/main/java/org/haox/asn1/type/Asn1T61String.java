package org.haox.asn1.type;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

public class Asn1T61String extends Asn1String
{
    public Asn1T61String() {
        super(BerTag.T61_STRING);
    }

    public Asn1T61String(String value) {
        super(value, BerTag.T61_STRING);
    }
}
