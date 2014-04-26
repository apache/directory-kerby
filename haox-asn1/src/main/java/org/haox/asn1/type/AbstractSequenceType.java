package org.haox.asn1.type;

import org.haox.asn1.*;

import java.io.IOException;
import java.nio.ByteBuffer;

/**
 * For sequence type that consists of tagged fields
 */
public abstract class AbstractSequenceType extends AbstractAsn1Type<AbstractSequenceType> {
    private Asn1Tag[] tags;
    private Asn1Type[] fields;

    public AbstractSequenceType() {
        super(TagClass.UNIVERSAL.getValue(), UniversalTag.SEQUENCE.getValue());
        setValue(this);
        tags = getTags();
        fields = new Asn1Type[tags.length];
    }

    protected abstract Asn1Tag[] getTags();

    @Override
    public byte[] encode() {
        return encode(Asn1Option.DER);
    }

    @Override
    public void encode(ByteBuffer buffer) {
        encode(buffer, Asn1Option.DER);
    }

    @Override
    protected int encodingBodyLength(Asn1Option option) {
        int allLen = 0;
        for (Asn1Type field : fields) {
            if (field != null) {
                allLen += ((AbstractAsn1Type) field).encodingLength(option);
            }
        }
        return allLen;
    }

    @Override
    protected void encodeBody(ByteBuffer buffer, Asn1Option option) {
        for (Asn1Type field : fields) {
            if (field != null) {
                field.encode(buffer, option);
            }
        }
    }

    @Override
    protected void decodeBody(LimitedByteBuffer content) throws IOException {
        Asn1Sequence sequence = new Asn1Sequence();
        sequence.decode(tag(), tagNo(), content);

        for (Asn1SequenceField field : sequence.getFields()) {
            Asn1Tag tag = getTag(field.getTagNo());
            Class<? extends Asn1Type> type = tag.getType();
            field.decodeAs(type);
            fields[tag.getIndex()] = field.getFieldValue();
        }
    }

    protected Asn1Tag getTag(int tagNo) {
        for (Asn1Tag tag : tags) {
            if (tag.getTag() == tagNo) {
                return tag;
            }
        }
        return null;
    }

    protected <T extends Asn1Type> T getFieldAs(int index, Class<T> t) {
        Asn1Type value = fields[index];
        if (value == null) return null;
        return (T) value;
    }

    protected void setFieldAs(int index, Asn1Type value) {
        fields[index] = value;
    }

    protected String getFieldAsString(int index) {
        Asn1Type value = fields[index];
        if (value == null) return null;

        if (value instanceof Asn1String) {
            return ((Asn1String) value).getValue();
        }

        throw new RuntimeException("The targeted field type isn't of string");
    }

    public byte[] getFieldAsOctets(int index) {
        Asn1OctetString value = getFieldAs(index, Asn1OctetString.class);
        if (value != null) return value.getValue();
        return null;
    }

    public void setFieldAsOctets(int index, byte[] bytes) {
        Asn1OctetString value = new Asn1OctetString(bytes);
        setFieldAs(index, value);
    }

    public Integer getFieldAsInteger(int index) {
        Asn1Integer value = getFieldAs(index, Asn1Integer.class);
        if (value != null) {
            return value.getValue().intValue();
        }
        return null;
    }

    public void setFieldAsInt(int index, int value) {
        setFieldAs(index, new Asn1Integer(value));
    }

    public byte[] getFieldAsOctetBytes(int index) {
        Asn1OctetString value = getFieldAs(index, Asn1OctetString.class);
        if (value != null) {
            return value.getValue();
        }
        return null;
    }

    public void setFieldAsOctetBytes(int index, byte[] value) {
        setFieldAs(index, new Asn1OctetString(value));
    }
}
