package org.haox.asn1;

import org.haox.asn1.type.Asn1Type;

public class Asn1Tag {
    private int index;
    private int tag;
    private Class<? extends Asn1Type> type;

    public Asn1Tag(int tag, Class<? extends Asn1Type> type) {
        this(tag, tag, type);
    }

    public Asn1Tag(int index, int tag, Class<? extends Asn1Type> type) {
        this.index = index;
        this.tag = tag;
        this.type = type;
    }

    public int getTag() {
        return tag;
    }

    public int getIndex() {
        return index;
    }

    public Class<? extends Asn1Type> getType() {
        return type;
    }
}
