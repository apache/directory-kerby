package org.apache.haox.asn1.type;

/**
 * For tagging a sequence type with tagNo, either application specific or context specific class
 */
public class TaggingSequence extends TaggingCollection {

    public TaggingSequence(int taggingTagNo, Asn1FieldInfo[] tags, boolean isAppSpecific) {
        super(taggingTagNo, tags, isAppSpecific);
    }

    @Override
    protected Asn1CollectionType createTaggedCollection(Asn1FieldInfo[] tags) {
        return new Asn1SequenceType(tags);
    }
}
