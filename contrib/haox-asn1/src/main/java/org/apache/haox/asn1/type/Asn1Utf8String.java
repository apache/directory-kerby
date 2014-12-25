package org.apache.haox.asn1.type;

import org.apache.haox.asn1.UniversalTag;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

public class Asn1Utf8String extends Asn1String
{
    public Asn1Utf8String() {
        this(null);
    }

    public Asn1Utf8String(String value) {
        super(UniversalTag.UTF8_STRING, value);
    }

    @Override
    protected void toBytes() {
        byte[] bytes = getValue().getBytes(StandardCharsets.UTF_8);
        setBytes(bytes);
    }

    protected void toValue() throws IOException {
        byte[] bytes = getBytes();
        setValue(new String(bytes, StandardCharsets.UTF_8));
    }
}
