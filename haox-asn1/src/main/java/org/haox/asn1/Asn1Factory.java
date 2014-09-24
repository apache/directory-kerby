package org.haox.asn1;

import org.haox.asn1.type.Asn1Collection;
import org.haox.asn1.type.Asn1Simple;
import org.haox.asn1.type.Asn1Type;

public class Asn1Factory {

    public static Asn1Type create(int tagNo) {
        UniversalTag tagNoEnum = UniversalTag.fromValue(tagNo);
        if (tagNoEnum != UniversalTag.UNKNOWN) {
            return create(tagNoEnum);
        }
        throw new IllegalArgumentException("Unexpected tag " + tagNo);
    }

    public static Asn1Type create(UniversalTag tagNo) {
        if (Asn1Simple.isSimple(tagNo)) {
            return Asn1Simple.createSimple(tagNo);
        } else if (Asn1Collection.isCollection(tagNo)) {
            return Asn1Collection.createCollection(tagNo);
        }
        throw new IllegalArgumentException("Unexpected tag " + tagNo);
    }
}
