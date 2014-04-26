package org.haox.asn1.type;

import org.haox.asn1.Asn1Option;
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
        return encode(Asn1Option.PRIMITIVE);
    }

    @Override
    public void encode(ByteBuffer buffer) {
        encode(buffer, Asn1Option.PRIMITIVE);
    }

    protected byte[] getBytes() {
        return bytes;
    }

    protected void setBytes(byte[] bytes) {
        this.bytes = bytes;
    }

    @Override
    public void encode(ByteBuffer buffer, Asn1Option option) {
        buffer.put((byte) makeTag(option));
        buffer.put((byte) encodingBodyLength(option));
        buffer.put(encodeBody(option));
    }

    protected byte[] encodeBody(Asn1Option option) {
        if (bytes == null) {
            toBytes(option);
        }
        return bytes;
    }

    @Override
    protected int encodingBodyLength(Asn1Option option) {
        if (bytes == null) {
            toBytes(option);
        }
        return bytes.length;
    }

    @Override
    protected void decodeBody(LimitedByteBuffer content) throws IOException {
        setBytes(content.readAllBytes());
        toValue();
    }

    protected void toValue() throws IOException {}

    protected void toBytes(Asn1Option option) {}
}
