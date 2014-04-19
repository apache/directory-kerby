package org.haox.asn1.type;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

public class Asn1Utf8String extends Asn1String
{
    public Asn1Utf8String() {
        super(BerTag.UTF8_STRING);
    }

    public Asn1Utf8String(String value) {
        super(value, BerTag.UTF8_STRING);
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
