package org.apache.haox.asn1;

public class TaggingOption
{
    private int tagNo;
    private boolean isImplicit;
    private boolean isAppSpecific;

    public static TaggingOption newImplicitAppSpecific(int tagNo) {
        return new TaggingOption(tagNo, true, true);
    }

    public static TaggingOption newExplicitAppSpecific(int tagNo) {
        return new TaggingOption(tagNo, false, true);
    }

    public static TaggingOption newImplicitContextSpecific(int tagNo) {
        return new TaggingOption(tagNo, true, false);
    }

    public static TaggingOption newExplicitContextSpecific(int tagNo) {
        return new TaggingOption(tagNo, false, false);
    }

    private TaggingOption(int tagNo, boolean isImplicit, boolean isAppSpecific) {
        this.tagNo = tagNo;
        this.isImplicit = isImplicit;
        this.isAppSpecific = isAppSpecific;
    }

    public int tagFlags(boolean isTaggedConstructed) {
        boolean isConstructed = isImplicit ? isTaggedConstructed : true;
        TagClass tagClass = isAppSpecific ? TagClass.APPLICATION : TagClass.CONTEXT_SPECIFIC;
        int flags = tagClass.getValue() | (isConstructed ? EncodingOption.CONSTRUCTED_FLAG : 0x00);
        return flags;
    }

    public int getTagNo() {
        return tagNo;
    }

    public boolean isAppSpecific() {
        return isAppSpecific;
    }

    public boolean isImplicit() {
        return isImplicit;
    }
}
