package org.haox.asn1.type;

import org.haox.asn1.TaggingOption;

public class Asn1FieldInfo {
    private int index;
    private int tagNo;
    private boolean isImplicit;
    private Class<? extends Asn1Type> type;

    public Asn1FieldInfo(int index, int tagNo, Class<? extends Asn1Type> type) {
        this(index, tagNo, type, false);
    }

    public Asn1FieldInfo(int index, Class<? extends Asn1Type> type) {
        this(index, index, type, false);
    }

    public Asn1FieldInfo(int index, Class<? extends Asn1Type> type, boolean isImplicit) {
        this(index, index, type, isImplicit);
    }

    public Asn1FieldInfo(int index, int tagNo, Class<? extends Asn1Type> type, boolean isImplicit) {
        this.index = index;
        this.tagNo = tagNo;
        this.type = type;
        this.isImplicit = isImplicit;
    }

    public boolean isTagged() {
        return tagNo != -1;
    }

    public TaggingOption getTaggingOption() {
        if (isImplicit) {
            return TaggingOption.newImplicitContextSpecific(tagNo);
        } else {
            return TaggingOption.newExplicitContextSpecific(tagNo);
        }
    }

    public int getTagNo() {
        return tagNo;
    }

    public int getIndex() {
        return index;
    }

    public boolean isImplicit() {
        return isImplicit;
    }

    public Class<? extends Asn1Type> getType() {
        return type;
    }
}
