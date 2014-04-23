package org.haox.asn1.type;

import org.haox.asn1.Asn1Option;
import org.haox.asn1.LimitedByteBuffer;

import java.io.IOException;
import java.nio.ByteBuffer;

public class Asn1AppSpecific extends AbstractAsn1Type<Asn1Type> {
    private int tagNo;

    public Asn1AppSpecific(int tagNo, Asn1Type value) {
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
    public void encode(ByteBuffer buffer, Asn1Option option) {

    }
}
