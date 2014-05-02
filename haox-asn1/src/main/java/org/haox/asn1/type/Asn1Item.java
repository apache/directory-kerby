package org.haox.asn1.type;

import org.haox.asn1.EncodingOption;
import org.haox.asn1.LimitedByteBuffer;
import org.haox.asn1.TagClass;

import java.io.IOException;

public class Asn1Item extends AbstractAsn1Type<Asn1Type>
{
    private int tag = -1;
    private int tagNo = -1;
    private LimitedByteBuffer bodyContent;

    public Asn1Item(Asn1Type value) {
        super(value.tagClass(), value.tagNo(), value);
        this.tag = value.tag();
        this.tagNo = value.tagNo();
    }

    public Asn1Item(int tag, int tagNo, LimitedByteBuffer bodyContent) {
        super(TagClass.fromTag(tag), tagNo);
        this.tag = tag;
        this.tagNo = tagNo;
        this.bodyContent = bodyContent;
    }

    public int getTag() {
        return tag;
    }

    public int getTagNo() {
        return tagNo;
    }

    public LimitedByteBuffer getBodyContent() {
        return bodyContent;
    }

    @Override
    protected boolean isConstructed() {
        return (tag & EncodingOption.CONSTRUCTED_FLAG) != 0;
    }

    @Override
    protected int encodingBodyLength() {
        if (isFullyDecoded()) {
            return ((AbstractAsn1Type) getValue()).encodingBodyLength();
        }
        return (int) bodyContent.hasLeft();
    }

    @Override
    protected void decodeBody(LimitedByteBuffer bodyContent) throws IOException {
        this.bodyContent = bodyContent;
    }

    @Override
    public Asn1Type getValue() {
        if (isFullyDecoded()) {
            return super.getValue();
        } else {
            try {
                decodeValue();
            } catch (IOException e) {
                throw new RuntimeException("Failed to decode value", e);
            }
        }
        return super.getValue();
    }

    public boolean isFullyDecoded() {
        return super.getValue() != null;
    }

    public void decodeValue() throws IOException {
        Class<? extends Asn1Type> type = null;
        decodeValueAs(type);
    }

    public void decodeValueAs(Class<? extends Asn1Type> type) throws IOException {
        Asn1Type value;
        try {
            value = type.newInstance();
        } catch (Exception e) {
            throw new RuntimeException("Invalid type: " + type.getCanonicalName(), e);
        }
        setValue(value);
        ((AbstractAsn1Type) value).decode(tag, tagNo, bodyContent);
    }
}
