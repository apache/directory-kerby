package org.haox.asn1.type;

import org.haox.asn1.*;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

public class Asn1Sequence extends AbstractAsn1Type<List<Asn1Type>>
{
    private List<Asn1SequenceField> fields;

    public Asn1Sequence() {
        super(TagClass.UNIVERSAL.getValue(), UniversalTag.SEQUENCE.getValue());
        this.fields = new ArrayList<Asn1SequenceField>();
        setValue(new ArrayList<Asn1Type>());
    }

    @Override
    public byte[] encode() {
        return encode(EncodingOption.DER);
    }

    @Override
    public void encode(ByteBuffer buffer) {
        encode(buffer, EncodingOption.DER);
    }

    @Override
    protected boolean isConstructed(EncodingOption encodingOption) {
        return true;
    }

    @Override
    public List<Asn1Type> getValue() {
        toValue();
        return super.getValue();
    }

    private void toValue() {
        if (getValue().isEmpty()) {
            List<Asn1Type> value = getValue();
            for (Asn1SequenceField field: fields) {
                if (field != null) {
                    value.add(field.getFieldValue());
                }
            }
        }
    }

    protected List<Asn1SequenceField> getFields() {
        return fields;
    }

    public void addField(Asn1Type fieldValue) {
        getValue().add(fieldValue);
    }

    @Override
    protected int encodingBodyLength(EncodingOption encodingOption) {
        List<Asn1Type> value = getValue();
        int allLen = 0;
        for (Asn1Type part : value) {
            if (part != null) {
                allLen += ((AbstractAsn1Type) part).encodingLength(encodingOption);
            }
        }
        return allLen;
    }

    @Override
    protected void encodeBody(ByteBuffer buffer, EncodingOption encodingOption) {
        List<Asn1Type> value = getValue();
        for (Asn1Type part : value) {
            if (part != null) {
                part.encode(buffer, encodingOption);
            }
        }
    }

    @Override
    protected void decodeBody(LimitedByteBuffer content) throws IOException {
        while (content.available()) {
            Asn1SequenceField aValue = decodeOne(content);
            if (aValue != null) {
                fields.add(aValue);
            } else {
                throw new RuntimeException("Unexpected running into here");
            }
        }
    }

    private static Asn1SequenceField decodeOne(LimitedByteBuffer content) throws IOException {
        int tag = readTag(content);
        int tagNo = readTagNo(content, tag);
        boolean isConstructed = (tag & CONSTRUCTED_FLAG) != 0;
        int length = readLength(content);
        if (length < 0) {
            throw new IOException("Unexpected length");
        }
        LimitedByteBuffer valueContent = new LimitedByteBuffer(content, length);

        Asn1SequenceField value = null;
        TagClass tagClass = TagClass.fromTag(tag);
        if (tagClass.isTagged()) {
            value = decodeTagged(tag, tagNo, valueContent);
        } else {
            UniversalTag tagEnum = UniversalTag.fromValue(tagNo);
            if (isConstructed) {
                value = createConsructed(tag, tagEnum, valueContent);
            } else {
                Asn1Type aValue = createPrimitive(tag, tagEnum, valueContent);
                value = new Asn1SequenceField(tag, tagNo, aValue);
            }
        }

        return value;
    }

    private static Asn1Type createPrimitive(int tag, UniversalTag tagNo, LimitedByteBuffer content) throws IOException {
        Asn1Type result = Asn1Factory.create(tagNo);
        ((AbstractAsn1Type)result).decode(tag, tagNo.getValue(), content);
        return result;
    }

    private static Asn1SequenceField createConsructed(int tag, UniversalTag tagNo, LimitedByteBuffer content) {
        return new Asn1SequenceField(tag, tagNo.getValue(), content);
    }

    private static Asn1SequenceField decodeTagged(int tag, int tagNo, LimitedByteBuffer content) throws IOException {
        return new Asn1SequenceField(tag, tagNo, content);
    }
}
