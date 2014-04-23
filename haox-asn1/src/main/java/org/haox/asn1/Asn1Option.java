package org.haox.asn1;

public enum Asn1Option
{
    UNKNOWN(-1),
    IMPLICIT(1),
    EXPLICIT(2);

    private int value;

    private Asn1Option(int value) {
        this.value = value;
    }

    public int getValue() {
        return value;
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
