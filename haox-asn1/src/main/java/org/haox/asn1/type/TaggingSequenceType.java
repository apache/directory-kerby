package org.haox.asn1.type;

import org.haox.asn1.Asn1Tag;
import org.haox.asn1.EncodingOption;
import org.haox.asn1.LimitedByteBuffer;
import org.haox.asn1.TagClass;

import java.io.IOException;
import java.nio.ByteBuffer;

/**
 * For tagging a sequence type with tagNo, either application specific or context specific class
 */
public class TaggingSequenceType extends AbstractAsn1Type<SequenceType> {
    private Asn1Tagging<SequenceType> tagging;
    private SequenceType tagged;

    public TaggingSequenceType(int tagNo, Asn1Tag[] tags, boolean isAppSpecific) {
        super((isAppSpecific ? TagClass.APPLICATION : TagClass.CONTEXT_SPECIFIC).getValue(), tagNo);
        this.tagged = new SequenceType(tags);
        setValue(tagged);
        this.tagging = new Asn1Tagging<SequenceType>(tagNo, tagged, isAppSpecific);
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
        return tagging.isConstructed(encodingOption);
    }

    @Override
    protected int encodingBodyLength(EncodingOption encodingOption) {
        return tagging.encodingBodyLength(encodingOption);
    }

    @Override
    protected void encodeBody(ByteBuffer buffer, EncodingOption encodingOption) {
        tagging.encodeBody(buffer, encodingOption);
    }

    @Override
    protected void decodeBody(LimitedByteBuffer content) throws IOException {
        tagging.decodeBody(content);
    }

    protected Asn1Tag getTag(int tagNo) {
        return tagged.getTag(tagNo);
    }

    protected <T extends Asn1Type> T getFieldAs(int index, Class<T> t) {
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
