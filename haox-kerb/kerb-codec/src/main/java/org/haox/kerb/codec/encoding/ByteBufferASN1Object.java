package org.haox.kerb.codec.encoding;

import org.bouncycastle.asn1.AbstractASN1Primitive;

import java.nio.ByteBuffer;

public class ByteBufferASN1Object extends AbstractASN1Primitive
{
    private final ByteBuffer byteBuffer;
    private final int limit;

    public ByteBufferASN1Object(ByteBuffer byteBuffer, int limit) {
        super();
        this.byteBuffer = byteBuffer;
        this.limit = limit;
    }

    public ByteBuffer getByteBuffer() {
        return byteBuffer;
    }

    public int getLimit() {
        return limit;
    }

    public byte[] toByteArray() {
        return HaoxASN1InputStream.fromByteBuffer(byteBuffer, limit);
    }
}