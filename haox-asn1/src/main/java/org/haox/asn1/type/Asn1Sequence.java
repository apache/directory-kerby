package org.haox.asn1.type;

import org.haox.asn1.TagClass;
import org.haox.asn1.UniversalTag;

public class Asn1Sequence extends Asn1Collection
{
    public Asn1Sequence() {
        super(TagClass.UNIVERSAL, UniversalTag.SEQUENCE.getValue());
    }
}
