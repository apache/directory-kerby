package org.haox.asn1.type;

import org.haox.asn1.TagClass;
import org.haox.asn1.UniversalTag;

public class Asn1SequenceOf<T extends Asn1Type> extends Asn1CollectionOf<T>
{
    public Asn1SequenceOf() {
        super(TagClass.UNIVERSAL, UniversalTag.SEQUENCE_OF.getValue());
    }

    public boolean isEmpty() {
        return (getValue() == null || getElements().size() == 0);
    }

    public void add(T element) {
        getElements().add(element);
    }
}
