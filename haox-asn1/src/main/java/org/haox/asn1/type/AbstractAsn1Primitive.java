package org.haox.asn1.type;

import java.nio.ByteBuffer;

public abstract class AbstractAsn1Primitive<T> extends AbstractAsn1Type implements Asn1PrimitiveType<T> {
    private T value;

    public AbstractAsn1Primitive(BerTag tag) {
        this(null, tag);
    }

    public AbstractAsn1Primitive(T value, BerTag tag) {
        super(tag.getValue());
        setValue(value);
    }

    @Override
    public T getValue() {
        return value;
    }

    protected void setValue(T value) {
        this.value = value;
    }

    @Override
    public void encode(ByteBuffer buffer) {
        buffer.put((byte) tag());
        buffer.put((byte) bodyLength());
        buffer.put(body());
    }

    protected abstract byte[] body();

    @Override
    protected boolean isConstructed() {
        return false;
    }
}
