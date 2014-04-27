package org.haox.asn1;

import org.haox.asn1.type.AbstractAsn1Type;
import org.haox.asn1.type.Asn1Type;

public class TaggingOption
{
    private int tagNo;
    private boolean isConstructed;
    private boolean isAppSpecific;

    public TaggingOption(int tagNo, boolean isAppSpecific) {
        this.tagNo = tagNo;
        this.isAppSpecific = isAppSpecific;
    }

    public int getTag(EncodingOption encodingOption) {
        boolean isConstructed = encodingOption.isConstructed();
        TagClass tagClass = isAppSpecific() ? TagClass.APPLICATION : TagClass.CONTEXT_SPECIFIC;
        int taggingTag = tagClass.getValue() | (isConstructed ? 0x20 : 0x00) | getTagNo();
        return taggingTag;
    }

    public int getTagNo() {
        return tagNo;
    }

    public boolean isAppSpecific() {
        return isAppSpecific;
    }
}
