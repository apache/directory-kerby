package org.haox.asn1.type;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

public class Asn1Utf8String extends Asn1String
{
    private byte[] bytes;

    public Asn1Utf8String() {
        super(BerTag.UTF8_STRING);
    }

    public Asn1Utf8String(String value) {
        super(value, BerTag.UTF8_STRING);
    }

    @Override
    protected byte[] body() {
        if (bytes == null) {
            toBytes();
        }
        return bytes;
    }

    @Override
    protected int bodyLength() {
        if (bytes == null) {
            toBytes();
        }
        return bytes.length;
    }

    private void toBytes() {
        this.bytes = getValue().getBytes(StandardCharsets.UTF_8);
    }

    @Override
    protected void decodeValue(int length, LimitedByteBuffer content) throws IOException {
        byte[] bytes = content.readBytes(length);
        setValue(new String(bytes, StandardCharsets.UTF_8));
    }
}
