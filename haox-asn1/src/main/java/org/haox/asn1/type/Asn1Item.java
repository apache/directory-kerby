package org.haox.asn1.type;

import org.haox.asn1.LimitedByteBuffer;

import java.io.IOException;

public class Asn1Item
{
    private Asn1Type value;

    private int tag = -1;
    private int tagNo = -1;
    private LimitedByteBuffer content;

    public Asn1Item(Asn1Type value) {
        this.value = value;
        this.tag = value.tag();
        this.tagNo = value.tagNo();
    }

    public Asn1Item(int tag, int tagNo, LimitedByteBuffer content) {
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

    public Asn1Type getValue() {
        return value;
    }

    public boolean isFullyDecoded() {
        return value != null && tag != -1;
    }

    public void decodeValueAs(Class<? extends Asn1Type> type) throws IOException {
        try {
            value = type.newInstance();
        } catch (Exception e) {
            e.printStackTrace();
        }

        ((AbstractAsn1Type) value).decode(tag, tagNo, content);
    }
}
