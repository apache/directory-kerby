package org.haox.asn1.type;

import org.haox.asn1.EncodingOption;
import org.haox.asn1.LimitedByteBuffer;
import org.haox.asn1.TagClass;
import org.haox.asn1.UniversalTag;

import java.io.IOException;
import java.nio.ByteBuffer;

public abstract class AbstractAsn1Simple<T> extends AbstractAsn1Type<T> {
    private byte[] bytes;

    public AbstractAsn1Simple(UniversalTag tagNo) {
        this(tagNo, null);
    }

    public AbstractAsn1Simple(UniversalTag tagNo, T value) {
        super(TagClass.UNIVERSAL.getValue(), tagNo.getValue(), value);
        setEncodingOption(EncodingOption.PRIMITIVE);
    }

    protected byte[] getBytes() {
        return bytes;
    }

    protected void setBytes(byte[] bytes) {
        this.bytes = bytes;
    }

    @Override
    public void encode(ByteBuffer buffer) {
        buffer.put((byte) makeTag());
        buffer.put((byte) encodingBodyLength());
        buffer.put(encodeBody());
    }

    protected byte[] encodeBody() {
        if (bytes == null) {
            toBytes(encodingOption);
        }
        return bytes;
    }

    @Override
    protected void encodeBody(ByteBuffer buffer) {
        buffer.put(encodeBody());
    }

    @Override
    protected int encodingBodyLength() {
        if (bytes == null) {
            toBytes(encodingOption);
        }
        return bytes.length;
    }

    @Override
    protected void decodeBody(LimitedByteBuffer content) throws IOException {
        setBytes(content.readAllBytes());
        toValue();
    }

    @Override
    protected boolean isConstructed() {
        return false;
    }

    protected void toValue() throws IOException {}

    protected void toBytes(EncodingOption encodingOption) {}
}
