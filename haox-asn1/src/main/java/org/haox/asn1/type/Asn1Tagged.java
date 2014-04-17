package org.haox.asn1.type;

import java.io.IOException;
import java.nio.ByteBuffer;

public class Asn1Tagged extends AbstractAsn1Type<Asn1Type> {
    private int tagNo;

    public Asn1Tagged(int tagNo, Asn1Type value) {
        super(value.tag(), value);
        this.tagNo = tagNo;
    }

    public int getTagNo() {
        return tagNo;
    }

    @Override
    protected int bodyLength() {
        return 0;
    }

    @Override
    protected void decodeValue(LimitedByteBuffer content) throws IOException {

    }

    @Override
    public void encode(ByteBuffer buffer) {

    }
}
