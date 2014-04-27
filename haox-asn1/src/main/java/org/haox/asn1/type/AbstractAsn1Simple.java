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
    }

    @Override
    public byte[] encode() {
        return encode(EncodingOption.PRIMITIVE);
    }

    @Override
    public void encode(ByteBuffer buffer) {
        encode(buffer, EncodingOption.PRIMITIVE);
    }

    protected byte[] getBytes() {
        return bytes;
    }

    protected void setBytes(byte[] bytes) {
        this.bytes = bytes;
    }

    @Override
    public void encode(ByteBuffer buffer, EncodingOption encodingOption) {
        buffer.put((byte) makeTag(encodingOption));
        buffer.put((byte) encodingBodyLength(encodingOption));
        buffer.put(encodeBody(encodingOption));
    }

    protected byte[] encodeBody(EncodingOption encodingOption) {
        if (bytes == null) {
            toBytes(encodingOption);
        }
        return bytes;
    }

    @Override
    protected void encodeBody(ByteBuffer buffer, EncodingOption encodingOption) {
        buffer.put(encodeBody(encodingOption));
    }

    @Override
    protected int encodingBodyLength(EncodingOption encodingOption) {
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

    protected boolean isConstructed(EncodingOption encodingOption) {
        return false;
    }

    protected void toValue() throws IOException {}

    protected void toBytes(EncodingOption encodingOption) {}
}
