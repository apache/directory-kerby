package org.haox.asn1.type;

import org.haox.asn1.TagClass;
import org.haox.asn1.UniversalTag;

import java.lang.reflect.ParameterizedType;
import java.util.List;

public class Asn1SequenceOf<T extends Asn1Type> extends Asn1CollectionOf<T>
{
    public Asn1SequenceOf() {
        super(TagClass.UNIVERSAL, UniversalTag.SEQUENCE_OF.getValue());
    }
}
