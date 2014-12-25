package org.apache.haox.asn1;

public enum EncodingOption
{
    UNKNOWN(-1),
    PRIMITIVE(1),
    CONSTRUCTED(2),
    CONSTRUCTED_DEFLEN(3),
    CONSTRUCTED_INDEFLEN(4),
    IMPLICIT(5),
    EXPLICIT(6),
    BER(7),
    DER(8),
    CER(9);

    private int value;

    private EncodingOption(int value) {
        this.value = value;
    }

    public static int CONSTRUCTED_FLAG = 0x20;

    public static boolean isConstructed(int tag) {
        return (tag & CONSTRUCTED_FLAG) != 0;
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

    public static EncodingOption fromValue(int value) {
        for (EncodingOption e : values()) {
            if (e.getValue() == value) {
                return (EncodingOption) e;
            }
        }

        return UNKNOWN;
    }
}
