package org.haox.asn1;

public enum Asn1Option
{
    UNKNOWN(-1),
    PRIMITIVE(1),
    CONSTRUCTED(2),
    CONSTRUCTED_DEFLEN(3),
    CONSTRUCTED_INDEFLEN(4),
    IMPLICIT(5),
    EXPLICIT(6),
    DER(7),
    CER(8);

    private int value;

    private Asn1Option(int value) {
        this.value = value;
    }

    public int getValue() {
        return value;
    }

    public boolean isPrimitive() {
        return this == PRIMITIVE;
    }

    public boolean isConstructed() {
        return this == CONSTRUCTED || this == CONSTRUCTED_DEFLEN || this == CONSTRUCTED_INDEFLEN;
    }

    public boolean isImplicit() {
        return this == IMPLICIT;
    }

    public boolean isExplicit() {
        return this == EXPLICIT;
    }

    public boolean isDer() {
        return this == DER;
    }

    public boolean isCer() {
        return this == CER;
    }

    public static Asn1Option fromValue(int value) {
        for (Asn1Option e : values()) {
            if (e.getValue() == value) {
                return (Asn1Option) e;
            }
        }

        return UNKNOWN;
    }
}
