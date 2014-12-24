package org.haox.asn1.type;

/**
 * For tagging a sequence type with tagNo, either application specific or context specific class
 */
public class TaggingSet extends TaggingCollection {

    public TaggingSet(int taggingTagNo, Asn1FieldInfo[] tags, boolean isAppSpecific) {
        super(taggingTagNo, tags, isAppSpecific);
    }

    @Override
    protected Asn1CollectionType createTaggedCollection(Asn1FieldInfo[] tags) {
        return new Asn1SetType(tags);
    }
}
