package org.apache.haox.asn1.type;

import org.apache.haox.asn1.TagClass;
import org.apache.haox.asn1.UniversalTag;

public class Asn1SetOf<T extends Asn1Type> extends Asn1CollectionOf<T>
{
    public Asn1SetOf() {
        super(TagClass.UNIVERSAL, UniversalTag.SET_OF.getValue());
    }
}
