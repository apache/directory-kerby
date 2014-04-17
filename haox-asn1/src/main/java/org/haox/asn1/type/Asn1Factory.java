package org.haox.asn1.type;

public class Asn1Factory {

    public static Asn1Type create(BerTag tag) {
        Asn1Type value = null;
        switch (tag) {
            case BIT_STRING:
                value = new Asn1BitString();
            case BMP_STRING:
                value = new Asn1BmpString();
            case BOOLEAN:
                value = new Asn1Boolean();
            case ENUMERATED:
                value = null;
            case GENERALIZED_TIME:
                value = new Asn1GeneralizedTime();
            case GENERAL_STRING:
                value = new Asn1GeneralString();
            case IA5_STRING:
                value = new new Asn1IA5String();
            case INTEGER:
                value = new Asn1Integer();
            case NULL:
                value = new Asn1Null();
            case NUMERIC_STRING:
                value = new Asn1NumericsString();
            case OBJECT_IDENTIFIER:
                value = null;
            case OCTET_STRING:
                value = new Asn1OctetString();
            case PRINTABLE_STRING:
                value = new Asn1PrintableString();
            case T61_STRING:
                value = new Asn1T61String();
            case UNIVERSAL_STRING:
                value = new Asn1UniversalString();
            case UTC_TIME:
                value = new Asn1UtcTime();
            case UTF8_STRING:
                value = new Asn1Utf8String();
            case VISIBLE_STRING:
                value = new Asn1VisibleString();
            default:
                throw new IllegalArgumentException("Unexpected tag " + tag.getValue());
        }
        return value;
    }
}
