package org.haox.asn1.type;

public class Asn1Factory {

    public static Asn1Type create(BerTag tag) {
        switch (tag) {
            case BIT_STRING:
                return new Asn1BitString();
            case BMP_STRING:
                return new Asn1BmpString();
            case BOOLEAN:
                return new Asn1Boolean();
            case ENUMERATED:
                return null;
            case GENERALIZED_TIME:
                return new Asn1GeneralizedTime();
            case GENERAL_STRING:
                return new Asn1GeneralString();
            case IA5_STRING:
                return new Asn1IA5String();
            case INTEGER:
                return new Asn1Integer();
            case NULL:
                return new Asn1Null();
            case NUMERIC_STRING:
                return new Asn1NumericsString();
            case OBJECT_IDENTIFIER:
                return null;
            case OCTET_STRING:
                return new Asn1OctetString();
            case PRINTABLE_STRING:
                return new Asn1PrintableString();
            case T61_STRING:
                return new Asn1T61String();
            case UNIVERSAL_STRING:
                return new Asn1UniversalString();
            case UTC_TIME:
                return new Asn1UtcTime();
            case UTF8_STRING:
                return new Asn1Utf8String();
            case VISIBLE_STRING:
                return new Asn1VisibleString();
            default:
                throw new IllegalArgumentException("Unexpected tag " + tag.getValue());
        }
    }
}
