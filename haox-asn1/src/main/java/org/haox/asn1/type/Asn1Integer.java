package org.haox.asn1.type;

import java.io.IOException;
import java.math.BigInteger;

public class Asn1Integer extends AbstractAsn1Primitive<BigInteger>
{
    private byte[] bytes;

    public Asn1Integer() {
        this(0);
    }

    public Asn1Integer(int value) {
        this(BigInteger.valueOf(value));
    }

    public Asn1Integer(long value) {
        this(BigInteger.valueOf(value));
    }

    public Asn1Integer(BigInteger value) {
        super(value, BerTag.INTEGER);
        this.bytes = value.toByteArray();
    }

    @Override
    protected byte[] body() {
        return bytes;
    }

    @Override
    protected int bodyLength() {
        return bytes.length;
    }

    @Override
    protected void decodeValue(int length, LimitedByteBuffer content) throws IOException {
        byte[] bytes = content.readBytes(length);
        this.bytes = bytes;
        setValue(new BigInteger(bytes));
    }
}
