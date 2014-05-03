package org.haox.asn1;

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

    public int makeTag(boolean isTaggedConstructed) {
        boolean isConstructed = isImplicit ? isTaggedConstructed : true;
        TagClass tagClass = isAppSpecific ? TagClass.APPLICATION : TagClass.CONTEXT_SPECIFIC;
        int taggingTag = tagClass.getValue() | (isConstructed ? EncodingOption.CONSTRUCTED_FLAG : 0x00) | tagNo;
        return taggingTag;
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
