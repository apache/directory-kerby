package org.haox.asn1.type;

import java.io.IOException;

public class Asn1OctetString extends AbstractAsn1Primitive<byte[]>
{
    public Asn1OctetString() {
        super(null);
    }

    public Asn1OctetString(byte[] value) {
        super(value, BerTag.OCTET_STRING);
    }

    @Override
    protected byte[] body() {
        return getValue();
    }

    @Override
    protected int bodyLength() {
        return getValue().length;
    }

    @Override
    protected void decodeValue(LimitedByteBuffer content) throws IOException {
        setValue(content.readAllBytes());
    }
}
