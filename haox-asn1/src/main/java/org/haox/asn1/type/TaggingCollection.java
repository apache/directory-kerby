package org.haox.asn1.type;

import org.haox.asn1.EncodingOption;
import org.haox.asn1.LimitedByteBuffer;
import org.haox.asn1.TagClass;

import java.io.IOException;
import java.nio.ByteBuffer;

/**
 * For tagging a collection type with tagNo, either application specific or context specific class
 */
public abstract class TaggingCollection extends AbstractAsn1Type<Asn1CollectionType> {
    private Asn1Tagging<Asn1CollectionType> tagging;
    private Asn1CollectionType tagged;

    public TaggingCollection(int taggingTagNo, Asn1FieldInfo[] tags, boolean isAppSpecific) {
        super(isAppSpecific ? TagClass.APPLICATION : TagClass.CONTEXT_SPECIFIC, taggingTagNo);
        this.tagged = createTaggedCollection(tags);
        setValue(tagged);
        this.tagging = new Asn1Tagging<Asn1CollectionType>(taggingTagNo, tagged, isAppSpecific);
        setEncodingOption(EncodingOption.EXPLICIT);
    }

    protected abstract Asn1CollectionType createTaggedCollection(Asn1FieldInfo[] tags);

    public void setEncodingOption(EncodingOption encodingOption) {
        tagging.setEncodingOption(encodingOption);
    }

    @Override
    protected boolean isConstructed() {
        return tagging.isConstructed();
    }

    @Override
    protected int encodingBodyLength() {
        return tagging.encodingBodyLength();
    }

    @Override
    protected void encodeBody(ByteBuffer buffer) {
        tagging.encodeBody(buffer);
    }

    @Override
    protected void decodeBody(LimitedByteBuffer content) throws IOException {
        tagging.decodeBody(content);
    }

    protected Asn1FieldInfo getTag(int tagNo) {
        return tagged.getTag(tagNo);
    }

    public <T extends Asn1Type> T getFieldAs(int index, Class<T> t) {
        return tagged.getFieldAs(index, t);
    }

    protected void setFieldAs(int index, Asn1Type value) {
        tagged.setFieldAs(index, value);
    }

    protected String getFieldAsString(int index) {
        return tagged.getFieldAsString(index);
    }

    protected byte[] getFieldAsOctets(int index) {
        return tagged.getFieldAsOctets(index);
    }

    protected void setFieldAsOctets(int index, byte[] bytes) {
        tagged.setFieldAsOctets(index, bytes);
    }

    protected Integer getFieldAsInteger(int index) {
        return tagged.getFieldAsInteger(index);
    }

    protected void setFieldAsInt(int index, int value) {
        tagged.setFieldAsInt(index, value);
    }

    protected byte[] getFieldAsOctetBytes(int index) {
        return tagged.getFieldAsOctetBytes(index);
    }

    protected void setFieldAsOctetBytes(int index, byte[] value) {
        tagged.setFieldAsOctetBytes(index, value);
    }
}
