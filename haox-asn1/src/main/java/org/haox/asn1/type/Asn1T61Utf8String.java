package org.haox.asn1.type;

import org.haox.asn1.BerTag;
import org.haox.asn1.LimitedByteBuffer;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

public class Asn1T61Utf8String extends Asn1String
{
    private byte[] bytes;

    public Asn1T61Utf8String() {
        super(BerTag.T61_STRING);
    }

    public Asn1T61Utf8String(String value) {
        super(value, BerTag.T61_STRING);
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

    protected void toBytes() {
        this.bytes = getValue().getBytes(StandardCharsets.UTF_8);
    }

    @Override
    protected void decodeValue(LimitedByteBuffer content) throws IOException {
        byte[] bytes = content.readAllBytes();
        setValue(new String(bytes, StandardCharsets.UTF_8));
    }}
