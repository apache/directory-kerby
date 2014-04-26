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

    public Asn1SequenceField(int tag, int tagNo, Asn1Type fieldValue) {
        this.tag = tag;
        this.tagNo = tagNo;
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

    public boolean isFullyDecoded() {
        return fieldValue != null;
    }

    public void decodeAs(Class<? extends Asn1Type> type) throws IOException {
        try {
            fieldValue = type.newInstance();
        } catch (Exception e) {
            e.printStackTrace();
        }

        fieldValue.decode(tag, tagNo, content);
    }
}
