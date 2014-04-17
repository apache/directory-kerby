package org.haox.asn1.type;

import java.io.IOException;
import java.nio.ByteBuffer;

public abstract class TaggedSequenceType<T> extends AbstractAsn1Type<T> {
    public abstract Asn1Tag[] getTags();
    protected Asn1Type[] fields;

    public TaggedSequenceType() {
        this(-1);
    }

    public TaggedSequenceType(int tag) {
        super(tag);
        Asn1Tag[] tags = getTags();
        this.fields = new Asn1Type[tags.length];
    }

    @Override
    protected int bodyLength() {
        int allLen = 0;
        for (Asn1Type field : fields) {
            if (field != null) {
                allLen += field.encodingLength();
            }
        }
        return allLen;
    }

    @Override
    public void encode(ByteBuffer buffer) {
        buffer.put((byte) tag());
        buffer.put((byte) bodyLength());
        encodeBody(buffer);
    }

    private void encodeBody(ByteBuffer buffer) {
        Asn1Sequence sequence = new Asn1Sequence();
        for (Asn1Type field: fields) {
            if (field != null) {
                sequence.addField(field);
            }
        }
        sequence.encode(buffer);
    }

    @Override
    protected void decodeValue(LimitedByteBuffer content) throws IOException {
        Asn1Sequence sequence = new Asn1Sequence();
        sequence.decode(content);

        for (Asn1SequenceField field : sequence.getFields()) {
            Asn1Tag tag = getTag(field.getTagNo());
            Class<? extends Asn1Type> type = tag.getType();
            field.decodeAs(type);
            fields[tag.getIndex()] = field.getFieldValue();
        }
    }

    protected Asn1Tag getTag(int tagNo) {
        Asn1Tag[] tags = getTags();
        for (Asn1Tag tag : tags) {
            if (tag.getValue() == tagNo) {
                return tag;
            }
        }
        return null;
    }

    protected <T extends Asn1Type> T getFieldAs(Asn1Tag tag, Class<T> t) {
        return getFieldAs(tag.getIndex(), t);
    }

    protected String getFieldAsString(Asn1Tag tag) {
        Asn1Type value = fields[tag.getIndex()];
        if (value == null) return null;

        if (value instanceof Asn1String) {
            return ((Asn1String) value).getValue();
        }

        throw new RuntimeException("The targeted field type isn't of string");
    }

    protected <T extends Asn1Type> T getFieldAs(int index, Class<T> t) {
        Asn1Type value = fields[index];
        if (value == null) return null;
        return (T) value;
    }

    protected void setField(Asn1Tag tag, Asn1Type value) {
        setField(tag.getIndex(), value);
    }

    protected void setField(int index, Asn1Type value) {
        fields[index] = value;
    }
}
