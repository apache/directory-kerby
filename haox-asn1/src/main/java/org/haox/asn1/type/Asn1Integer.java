package org.haox.asn1.type;

import org.haox.asn1.BerTag;
import org.haox.asn1.LimitedByteBuffer;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;

public class Asn1Integer extends AbstractAsn1Primitive<Integer>
{
    private byte[] bytes;

    public Asn1Integer() {
        this(0);
    }

    public Asn1Integer(int value) {
        super(value, BerTag.INTEGER);
        this.bytes = ByteBuffer.allocate(4).putInt(value).array();
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
        setValue(new BigInteger(bytes).intValue());
    }
}
