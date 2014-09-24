package org.haox.asn1.type;

import org.haox.asn1.TagClass;
import org.haox.asn1.UniversalTag;

public class Asn1Set extends Asn1Collection
{
    public Asn1Set() {
        super(TagClass.UNIVERSAL, UniversalTag.SET.getValue());
    }
}
