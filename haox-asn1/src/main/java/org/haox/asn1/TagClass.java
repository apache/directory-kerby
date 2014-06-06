package org.haox.asn1;

public enum TagClass
{
    UNKNOWN(-1),
    UNIVERSAL(0x00),
    APPLICATION(0x40),
    CONTEXT_SPECIFIC(0x80),
    PRIVATE(0xC0);

    private int value;

    private TagClass(int value) {
        this.value = value;
    }

    public int getValue() {
        return value;
    }

    public boolean isUniversal() {
        return this == UNIVERSAL;
    }

    public boolean isAppSpecific() {
        return this == APPLICATION;
    }

    public boolean isContextSpecific() {
        return this == CONTEXT_SPECIFIC;
    }

    public boolean isTagged() {
        return this == APPLICATION || this == CONTEXT_SPECIFIC;
    }

    public static TagClass fromValue(int value) {
        for (TagClass e : values()) {
            if (e.getValue() == value) {
                return (TagClass) e;
            }
        }

        return UNKNOWN;
    }

    public static TagClass fromTagFlags(int tag) {
        return fromValue(tag & 0xC0);
    }
}
