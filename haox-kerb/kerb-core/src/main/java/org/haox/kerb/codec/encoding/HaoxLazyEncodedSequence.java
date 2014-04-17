package org.haox.kerb.codec.encoding;

import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.AbstractASN1Primitive;

import java.io.IOException;
import java.nio.ByteBuffer;

public class HaoxLazyEncodedSequence extends ByteBufferASN1Object
{
    public HaoxLazyEncodedSequence(ByteBuffer byteBuffer, int limit) {
        super(byteBuffer, limit);
    }
}