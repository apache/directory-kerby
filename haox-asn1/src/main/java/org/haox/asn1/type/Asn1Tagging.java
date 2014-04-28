package org.haox.asn1.type;

import org.haox.asn1.EncodingOption;
import org.haox.asn1.LimitedByteBuffer;
import org.haox.asn1.TagClass;

import java.io.IOException;
import java.lang.reflect.ParameterizedType;
import java.nio.ByteBuffer;

/**
 * For tagging any Asn1Type with a tagNo
 */
public class Asn1Tagging<T extends Asn1Type> extends AbstractAsn1Type<T> {

    public Asn1Tagging(boolean isAppSpecific) {
        this(-1, null, isAppSpecific);
    }

    public Asn1Tagging(int tagNo, T value, boolean isAppSpecific) {
        super(isAppSpecific ? TagClass.APPLICATION : TagClass.CONTEXT_SPECIFIC, tagNo, value);
        setEncodingOption(EncodingOption.EXPLICIT);
    }

    @Override
    protected int encodingBodyLength() {
        AbstractAsn1Type value = (AbstractAsn1Type) getValue();
        if (encodingOption.isExplicit()) {
            return value.encodingLength();
        } else if (encodingOption.isImplicit()) {
            return value.encodingBodyLength();
        } else {
            throw new RuntimeException("Invalid encoding option, only allowing explicit/implicit");
        }
    }

    @Override
    protected boolean isConstructed() {
        if (encodingOption.isExplicit()) {
            return true;
        } else if (encodingOption.isImplicit()) {
            AbstractAsn1Type value = (AbstractAsn1Type) getValue();
            return value.isConstructed();
        }
        return false;
    }

    @Override
    protected void encodeBody(ByteBuffer buffer) {
        AbstractAsn1Type value = (AbstractAsn1Type) getValue();
        if (encodingOption.isExplicit()) {
            value.encode(buffer);
        } else if (encodingOption.isImplicit()) {
            value.encodeBody(buffer);
        } else {
            throw new RuntimeException("Invalid encoding option, only allowing explicit/implicit");
        }
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
