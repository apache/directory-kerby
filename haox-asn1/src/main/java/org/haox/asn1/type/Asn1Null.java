package org.haox.asn1.type;

import java.io.IOException;

public class Asn1Null extends AbstractAsn1Primitive<Object>
{
    public static final Asn1Null NULL = new Asn1Null();
    private static final byte[]  EMPTY_BYTES = new byte[0];

    public Asn1Null() {
        super(null, BerTag.NULL);
    }

    @Override
    protected byte[] body() {
        return EMPTY_BYTES;
    }

    @Override
    protected int bodyLength() {
        return 0;
    }

    @Override
    protected void decodeValue(LimitedByteBuffer content) throws IOException {
        if (content.hasLeft() != 0) {
            throw new IOException("Unexpected bytes found for NULL");
        }
    }
}
