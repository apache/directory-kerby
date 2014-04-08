package org.haox.asn1.type;

import java.io.IOException;

public class Asn1BitString extends AbstractAsn1Primitive<byte[]>
{
    private int padding;

    public Asn1BitString() {
        super(null);
    }

    public Asn1BitString(byte[] value) {
        this(value, 0);
    }

    public Asn1BitString(byte[] value, int padding) {
        super(value, BerTag.BIT_STRING);
        this.padding = padding;
    }

    @Override
    protected byte[] body() {
        byte[] bytes = new byte[bodyLength()];
        bytes[0] = (byte)padding;
        System.arraycopy(getValue(), 0, bytes, 1, bytes.length - 1);
        return bytes;
    }

    @Override
    protected int bodyLength() {
        return getValue().length + 1;
    }

    @Override
    protected void decodeValue(int length, LimitedByteBuffer content) throws IOException {
        setValue(content.readBytes(length));
    }
}
