package org.haox.asn1.type;

import org.haox.asn1.*;

import java.io.IOException;
import java.nio.ByteBuffer;

/**
 * For sequence type that consists of tagged fields
 */
public class SequenceType extends AbstractAsn1Type<SequenceType> {
    private Asn1Tag[] tags;
    private Asn1Type[] fields;

    public SequenceType(Asn1Tag[] tags) {
        super(TagClass.UNIVERSAL, UniversalTag.SEQUENCE.getValue());
        setValue(this);
        this.tags = tags;
        fields = new Asn1Type[tags.length];
        setEncodingOption(EncodingOption.CONSTRUCTED);
    }

    @Override
    protected boolean isConstructed() {
        return true;
    }

    @Override
    protected int encodingBodyLength() {
        int allLen = 0;
        Asn1Type field;
        TaggingOption taggingOption;
        for (int i = 0; i < fields.length; ++i) {
            field = fields[i];
            if (field != null) {
                taggingOption = TaggingOption.newExplicitContextSpecific(tags[i].getTag());
                allLen += ((AbstractAsn1Type) field).taggedEncodingLength(taggingOption);
            }
        }
        return allLen;
    }

    @Override
    protected void encodeBody(ByteBuffer buffer) {
        Asn1Type field;
        TaggingOption taggingOption;
        for (int i = 0; i < fields.length; ++i) {
            field = fields[i];
            if (field != null) {
                taggingOption = TaggingOption.newExplicitContextSpecific(tags[i].getTag());
                field.taggedEncode(buffer, taggingOption);
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

    protected byte[] getFieldAsOctets(int index) {
        Asn1OctetString value = getFieldAs(index, Asn1OctetString.class);
        if (value != null) return value.getValue();
        return null;
    }

    protected void setFieldAsOctets(int index, byte[] bytes) {
        Asn1OctetString value = new Asn1OctetString(bytes);
        setFieldAs(index, value);
    }

    protected Integer getFieldAsInteger(int index) {
        Asn1Integer value = getFieldAs(index, Asn1Integer.class);
        if (value != null) {
            return value.getValue().intValue();
        }
        return null;
    }

    protected void setFieldAsInt(int index, int value) {
        setFieldAs(index, new Asn1Integer(value));
    }

    protected byte[] getFieldAsOctetBytes(int index) {
        Asn1OctetString value = getFieldAs(index, Asn1OctetString.class);
        if (value != null) {
            return value.getValue();
        }
        return null;
    }

    protected void setFieldAsOctetBytes(int index, byte[] value) {
        setFieldAs(index, new Asn1OctetString(value));
    }
}
