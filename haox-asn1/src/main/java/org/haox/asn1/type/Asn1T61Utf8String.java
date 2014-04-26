package org.haox.asn1.type;

import org.haox.asn1.UniversalTag;

import java.nio.charset.StandardCharsets;

public class Asn1T61Utf8String extends Asn1String
{
    public Asn1T61Utf8String() {
        this(null);
    }

    public Asn1T61Utf8String(String value) {
        super(UniversalTag.T61_STRING, value);
    }

    protected void toBytes() {
        setBytes(getValue().getBytes(StandardCharsets.UTF_8));
    }

    protected void toValue() {
        setValue(new String(getBytes(), StandardCharsets.UTF_8));
    }
}
