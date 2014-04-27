package org.haox.asn1.type;

import org.haox.asn1.EncodingOption;
import org.haox.asn1.UniversalTag;
import org.haox.asn1.LimitedByteBuffer;

import java.io.IOException;

public class Asn1Null extends AbstractAsn1Simple<Object>
{
    public static final Asn1Null NULL = new Asn1Null();
    private static final byte[]  EMPTY_BYTES = new byte[0];

    public Asn1Null() {
        super(null, UniversalTag.NULL);
    }

    @Override
    protected byte[] encodeBody(EncodingOption encodingOption) {
        return EMPTY_BYTES;
    }

    @Override
    protected int encodingBodyLength(EncodingOption encodingOption) {
        return 0;
    }

    @Override
    protected void decodeBody(LimitedByteBuffer content) throws IOException {
        if (content.hasLeft() != 0) {
            throw new IOException("Unexpected bytes found for NULL");
        }
    }
}
