package org.haox.asn1.type;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

public class Asn1Sequence extends AbstractAsn1Type<List<Asn1Type>>
{
    private List<Asn1SequenceField> fields;

    public Asn1Sequence() {
        this(-1);
    }

    public Asn1Sequence(int tag) {
        super(tag);
        this.fields = new ArrayList<Asn1SequenceField>();
    }

    @Override
    public List<Asn1Type> getValue() {
        if (super.getValue() == null) {
            List<Asn1Type> value = new ArrayList<Asn1Type>();
            convertAndFill(value);
            setValue(value);
        }

        return super.getValue();
    }

    private void convertAndFill(List<Asn1Type> value) {
        for (Asn1SequenceField field: fields) {
            if (field != null) {
                value.add(field.getFieldValue()); //ZKTODO
            }
        }
    }

    public List<Asn1SequenceField> getFields() {
        return fields;
    }

    public void addField(Asn1Type fieldValue) {
        this.fields.add(new Asn1SequenceField(fieldValue));
    }

    @Override
    protected int bodyLength() {
        return 0;
    }

    @Override
    public void encode(ByteBuffer buffer) {
        buffer.put((byte) tag());
        buffer.put((byte) bodyLength());
        encodeBody(buffer);
    }

    private void encodeBody(ByteBuffer buffer) {
        for (Asn1SequenceField field: fields) {
            if (field != null) {
                field.encode(buffer);
            }
        }
    }

    @Override
    protected void decodeValue(LimitedByteBuffer content) throws IOException {
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
        boolean isConstructed = (tag & BerTag.CONSTRUCTED) != 0;
        int length = readLength(content);
        if (length < 0) {
            throw new IOException("Unexpected length");
        }
        LimitedByteBuffer valueContent = new LimitedByteBuffer(content, length);

        Asn1SequenceField value = null;
        if ((tag & BerTag.TAGGED) != 0) {
            value = decodeOne(valueContent);
        } else {
            BerTag tagEnum = BerTag.fromValue(tagNo);
            if (isConstructed) {
                value = createConsructed(tag, tagEnum, valueContent);
            } else {
                Asn1Type aValue = createPrimitive(tag, tagEnum, valueContent);
                value = new Asn1SequenceField(aValue);
            }
        }

        return value;
    }

    private static Asn1Type createPrimitive(int tag, BerTag tagNo, LimitedByteBuffer content) throws IOException {
        Asn1Type result = Asn1Factory.create(tagNo);
        result.decode(tag, tagNo.getValue(), content);
        return result;
    }

    private static Asn1SequenceField createConsructed(int tag, BerTag tagNo, LimitedByteBuffer content) {
        return new Asn1SequenceField(tag, tagNo.getValue(), content);
    }
}
