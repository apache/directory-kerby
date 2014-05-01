package org.haox.asn1.type;

import org.haox.asn1.*;

import java.io.IOException;
import java.nio.ByteBuffer;

/**
 * For collection type that may consist of tagged fields
 */
public abstract class Asn1CollectionType extends AbstractAsn1Type<Asn1CollectionType> {
    private Asn1FieldInfo[] fieldInfos;
    private Asn1Type[] fields;

    public Asn1CollectionType(int universalTagNo, Asn1FieldInfo[] fieldInfos) {
        super(TagClass.UNIVERSAL, universalTagNo);
        setValue(this);
        this.fieldInfos = fieldInfos;
        fields = new Asn1Type[fieldInfos.length];
        setEncodingOption(EncodingOption.CONSTRUCTED);
    }

    @Override
    protected boolean isConstructed() {
        return true;
    }

    @Override
    protected int encodingBodyLength() {
        int allLen = 0;
        AbstractAsn1Type field;
        TaggingOption taggingOption;
        for (int i = 0; i < fields.length; ++i) {
            field = (AbstractAsn1Type) fields[i];
            if (field != null) {
                if (fieldInfos[i].isTagged()) {
                    taggingOption = fieldInfos[i].getTaggingOption();
                    allLen += field.taggedEncodingLength(taggingOption);
                } else {
                    allLen += field.encodingLength();
                }
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
                if (fieldInfos[i].isTagged()) {
                    taggingOption = taggingOption = fieldInfos[i].getTaggingOption();
                    field.taggedEncode(buffer, taggingOption);
                } else {
                    field.encode(buffer);
                }
            }
        }
    }

    @Override
    protected void decodeBody(LimitedByteBuffer content) throws IOException {
        Asn1Collection coll = createCollection();
        coll.decode(tag(), tagNo(), content);

        for (Asn1Item field : coll.getValue()) {
            Asn1FieldInfo tag = getTag(field.getTagNo());
            Class<? extends Asn1Type> type = tag.getType();
            field.decodeValueAs(type);
            fields[tag.getIndex()] = field.getValue();
        }
    }

    protected abstract Asn1Collection createCollection();

    protected Asn1FieldInfo getTag(int tagNo) {
        for (Asn1FieldInfo tag : fieldInfos) {
            if (tag.getTagNo() == tagNo) {
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
