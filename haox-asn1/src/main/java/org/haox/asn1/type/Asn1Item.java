package org.haox.asn1.type;

import org.haox.asn1.*;

import java.io.IOException;
import java.nio.ByteBuffer;

/**
 * Asn1Item serves two purposes:
 * 1. Wrapping an existing Asn1Type value for Asn1Collection;
 * 2. Wrapping a half decoded value whose body content is left to be decoded later when appropriate.
 * Why not fully decoded at once? Lazy and decode on demand for collection, or impossible due to lacking
 * key parameters, like implicit encoded value for tagged value.
 *
 * For not fully decoded value, you tell your case using isSimple/isCollection/isTagged/isContextSpecific etc.,
 * then call decodeValueAsSimple/decodeValueAsCollection/decodeValueAsImplicitTagged/decodeValueAsExplicitTagged etc.
 * to decode it fully. Or if you have already derived the value holder or the holder type, you can use decodeValueWith
 * or decodeValueAs with your holder or hodler type.
 */
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
    public boolean isConstructed() {
        return (tag & EncodingOption.CONSTRUCTED_FLAG) != 0;
    }

    @Override
    protected int encodingBodyLength() {
        if (getValue() != null) {
            return ((AbstractAsn1Type) getValue()).encodingBodyLength();
        }
        return (int) bodyContent.hasLeft();
    }

    @Override
    protected void encodeBody(ByteBuffer buffer) {
        if (getValue() != null) {
            ((AbstractAsn1Type) getValue()).encodeBody(buffer);
        } else {
            try {
                buffer.put(bodyContent.readAllLeftBytes());
            } catch (IOException e) {
                throw new RuntimeException("Failed to read all left bytes from body content", e);
            }
        }
    }

    @Override
    protected void decodeBody(LimitedByteBuffer bodyContent) throws IOException {
        this.bodyContent = bodyContent;
    }

    public boolean isFullyDecoded() {
        return getValue() != null;
    }

    public void decodeValueAsSimple() throws IOException {
        if (getValue() != null) return;
        if (! isSimple()) {
            throw new IllegalArgumentException("Attempting to decode non-simple value as simple");
        }

        Asn1Type value = Asn1Factory.create(tagNo);
        decodeValueWith(value);
    }

    public void decodeValueAsCollection() throws IOException {
        if (getValue() != null) return;
        if (! isCollection()) {
            throw new IllegalArgumentException("Attempting to decode non-collection value as collection");
        }

        Asn1Type value = Asn1Factory.create(tagNo);
        decodeValueWith(value);
    }

    public void decodeValueAs(Class<? extends Asn1Type> type) throws IOException {
        Asn1Type value;
        try {
            value = type.newInstance();
        } catch (Exception e) {
            throw new RuntimeException("Invalid type: " + type.getCanonicalName(), e);
        }
        decodeValueWith(value);
    }

    public void decodeValueWith(Asn1Type value) throws IOException {
        setValue(value);
        ((AbstractAsn1Type) value).decode(tag, tagNo, bodyContent);
    }

    public void decodeValueAsImplicitTagged(int originalTag, int originalTagNo) throws IOException {
        if (! isTagged()) {
            throw new IllegalArgumentException("Attempting to decode non-tagged value using tagging way");
        }
        Asn1Item taggedValue = new Asn1Item(originalTag, originalTagNo, getBodyContent());
        decodeValueWith(taggedValue);
    }

    public void decodeValueAsExplicitTagged() throws IOException {
        if (! isTagged()) {
            throw new IllegalArgumentException("Attempting to decode non-tagged value using tagging way");
        }
        Asn1Item taggedValue = decodeOne(getBodyContent());
        decodeValueWith(taggedValue);
    }

    private void decodeValueWith(Asn1Item taggedValue) throws IOException {
        taggedValue.decodeValueAsSimple();
        if (taggedValue.isFullyDecoded()) {
            setValue(taggedValue.getValue());
        } else {
            setValue(taggedValue);
        }
    }

    public void decodeValueWith(Asn1Type value, TaggingOption taggingOption) throws IOException {
        if (! isTagged()) {
            throw new IllegalArgumentException("Attempting to decode non-tagged value using tagging way");
        }
        ((AbstractAsn1Type) value).taggedDecode(getTag(), getTagNo(), getBodyContent(), taggingOption);
        setValue(value);
    }
}
