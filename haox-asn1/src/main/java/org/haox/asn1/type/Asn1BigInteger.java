package org.haox.asn1.type;

import java.io.IOException;
import java.math.BigInteger;

public class Asn1BigInteger extends AbstractAsn1Primitive<BigInteger>
{
    private byte[] bytes;

    public Asn1BigInteger() {
        this(0);
    }

    public Asn1BigInteger(int value) {
        this(BigInteger.valueOf(value));
    }

    public Asn1BigInteger(long value) {
        this(BigInteger.valueOf(value));
    }

    public Asn1BigInteger(BigInteger value) {
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
    protected void decodeValue(LimitedByteBuffer content) throws IOException {
        byte[] bytes = content.readAllBytes();
        this.bytes = bytes;
        setValue(new BigInteger(bytes));
    }
}
