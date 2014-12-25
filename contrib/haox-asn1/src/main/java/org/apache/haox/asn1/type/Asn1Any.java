package org.apache.haox.asn1.type;

import org.apache.haox.asn1.LimitedByteBuffer;

import java.io.IOException;
import java.nio.ByteBuffer;

public class Asn1Any extends AbstractAsn1Type<Asn1Type> {

    public Asn1Any(Asn1Type anyValue) {
        super(anyValue.tagFlags(), anyValue.tagNo(), anyValue);
    }

    @Override
    protected int encodingBodyLength() {
        return ((AbstractAsn1Type) getValue()).encodingBodyLength();
    }

    @Override
    protected void encodeBody(ByteBuffer buffer) {
        ((AbstractAsn1Type) getValue()).encodeBody(buffer);
    }

    @Override
    protected void decodeBody(LimitedByteBuffer content) throws IOException {
        ((AbstractAsn1Type) getValue()).decodeBody(content);
    }
}
