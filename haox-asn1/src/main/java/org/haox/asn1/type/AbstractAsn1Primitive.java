package org.haox.asn1.type;

import java.io.IOException;
import java.nio.ByteBuffer;

public abstract class AbstractAsn1Primitive<T> extends AbstractAsn1Type<T> {
    private byte[] bytes;

    public AbstractAsn1Primitive(BerTag tag) {
        this(null, tag);
    }

    public AbstractAsn1Primitive(T value, BerTag tag) {
        super(tag.getValue());
        setValue(value);
    }

    protected byte[] getBytes() {
        return bytes;
    }

    protected void setBytes(byte[] bytes) {
        this.bytes = bytes;
    }

    @Override
    public void encode(ByteBuffer buffer) {
        buffer.put((byte) tag());
        buffer.put((byte) bodyLength());
        buffer.put(body());
    }

    protected byte[] body() {
        if (bytes == null) {
            toBytes();
        }
        return bytes;
    }

    @Override
    protected int bodyLength() {
        if (bytes == null) {
            toBytes();
        }
        return bytes.length;
    }

    protected void toBytes() {}

    @Override
    protected void decodeValue(LimitedByteBuffer content) throws IOException {
        bytes = content.readAllBytes();
        toValue();
    }

    protected void toValue() throws IOException {}

    @Override
    protected boolean isConstructed() {
        return false;
    }
}
