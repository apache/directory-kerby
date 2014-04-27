package org.haox.asn1.type;

import org.haox.asn1.EncodingOption;
import org.haox.asn1.UniversalTag;
import org.haox.asn1.LimitedByteBuffer;

import java.io.IOException;

public class Asn1OctetString extends AbstractAsn1Simple<byte[]>
{
    public Asn1OctetString() {
        super(null);
    }

    public Asn1OctetString(byte[] value) {
        super(UniversalTag.OCTET_STRING, value);
    }

    @Override
    protected byte[] encodeBody(EncodingOption encodingOption) {
        return getValue();
    }

    @Override
    protected int encodingBodyLength(EncodingOption encodingOption) {
        return getValue().length;
    }

    @Override
    protected void decodeBody(LimitedByteBuffer content) throws IOException {
        setValue(content.readAllBytes());
    }
}
