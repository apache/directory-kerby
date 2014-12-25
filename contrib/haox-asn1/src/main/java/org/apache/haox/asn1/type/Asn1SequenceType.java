package org.apache.haox.asn1.type;

import org.apache.haox.asn1.UniversalTag;

/**
 * For sequence type that consists of tagged fields
 */
public class Asn1SequenceType extends Asn1CollectionType {

    public Asn1SequenceType(Asn1FieldInfo[] tags) {
        super(UniversalTag.SEQUENCE.getValue(), tags);
    }

    @Override
    protected Asn1Collection createCollection() {
        return new Asn1Sequence();
    }
}
