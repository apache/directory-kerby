package org.haox.asn1.type;

import org.haox.asn1.LimitedByteBuffer;

import java.io.IOException;
import java.nio.ByteBuffer;

public class Asn1SequenceField
{
    private Asn1Type fieldValue;

    private int tag;
    private int tagNo;
    private LimitedByteBuffer content;

    public Asn1SequenceField(Asn1Type fieldValue) {
        this.fieldValue = fieldValue;
    }

    public Asn1SequenceField(int tag, int tagNo, LimitedByteBuffer content) {
        this.tag = tag;
        this.tagNo = tagNo;
        this.content = content;
    }

    public int getTag() {
        return tag;
    }

    public int getTagNo() {
        return tagNo;
    }

    public Asn1Type getFieldValue() {
        return fieldValue;
    }

    public void decode() throws IOException {
        fieldValue = null; // non-simple cases

        fieldValue.decode(tag, tagNo, content);
    }

    public void decodeAs(Class<? extends Asn1Type> type) throws IOException {
        fieldValue = null;

        fieldValue.decode(tag, tagNo, content);
    }

    public void encode(ByteBuffer buffer) {
        fieldValue.encode(buffer);
    }
}
