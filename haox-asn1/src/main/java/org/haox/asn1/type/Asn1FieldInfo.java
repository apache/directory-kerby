package org.haox.asn1.type;

public class Asn1FieldInfo {
    private int index;
    private int tag;
    private Class<? extends Asn1Type> type;

    public Asn1FieldInfo(int tagNo, Class<? extends Asn1Type> type) {
        this(tagNo, tagNo, type);
    }

    public Asn1FieldInfo(int index, int tagNo, Class<? extends Asn1Type> type) {
        this.index = index;
        this.tag = tagNo;
        this.type = type;
    }

    public int getTagNo() {
        return tag;
    }

    public int getIndex() {
        return index;
    }

    public Class<? extends Asn1Type> getType() {
        return type;
    }
}
