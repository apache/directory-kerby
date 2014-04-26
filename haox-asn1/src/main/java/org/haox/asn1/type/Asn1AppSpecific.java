package org.haox.asn1.type;

import org.haox.asn1.Asn1Option;
import org.haox.asn1.LimitedByteBuffer;
import org.haox.asn1.TagClass;

import java.io.IOException;
import java.lang.reflect.ParameterizedType;
import java.nio.ByteBuffer;

public class Asn1AppSpecific<T extends Asn1Type> extends AbstractAsn1Type<T> {
    public Asn1AppSpecific() {
        this(-1, null);
    }

    public Asn1AppSpecific(int tagNo, T value) {
        super(TagClass.APPLICATION.getValue(), tagNo, value);
    }

    @Override
    public byte[] encode() {
        return encode(Asn1Option.EXPLICIT);
    }

    @Override
    public void encode(ByteBuffer buffer) {
        encode(buffer, Asn1Option.EXPLICIT);
    }

    @Override
    public void encode(ByteBuffer buffer, Asn1Option option) {
        buffer.put((byte) makeTag(Asn1Option.CONSTRUCTED));
        buffer.put((byte) encodingBodyLength(option));
        encodeBody(buffer, option);
    }

    @Override
    protected int encodingBodyLength(Asn1Option option) {
        AbstractAsn1Type value = (AbstractAsn1Type) getValue();
        return value.encodingLength(option);
    }

    @Override
    protected void encodeBody(ByteBuffer buffer, Asn1Option option) {
        Asn1Type value = getValue();
        value.encode(buffer, option);
    }

    @Override
    protected void decodeBody(LimitedByteBuffer content) throws IOException {
        Asn1Sequence sequence = new Asn1Sequence();
        sequence.decode(content);
        Asn1SequenceField field = sequence.getFields().get(0);
        if (!field.isFullyDecoded()) {
            Class<T> type = (Class<T>) ((ParameterizedType) getClass().getGenericSuperclass()).getActualTypeArguments()[0];
            field.decodeAs(type);
        }
        setValue((T) field.getFieldValue());
    }
}
