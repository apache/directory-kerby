package org.apache.haox.asn1.type;

import org.apache.haox.asn1.TagClass;
import org.apache.haox.asn1.UniversalTag;

public class Asn1Set extends Asn1Collection
{
    public Asn1Set() {
        super(TagClass.UNIVERSAL, UniversalTag.SET.getValue());
    }
}
