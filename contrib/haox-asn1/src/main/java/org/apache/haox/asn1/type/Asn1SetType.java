package org.apache.haox.asn1.type;

import org.apache.haox.asn1.UniversalTag;

/**
 * For set type that consists of tagged fields
 */
public class Asn1SetType extends Asn1CollectionType {

    public Asn1SetType(Asn1FieldInfo[] tags) {
        super(UniversalTag.SET.getValue(), tags);
    }

    @Override
    protected Asn1Collection createCollection() {
        return new Asn1Set();
    }
}
