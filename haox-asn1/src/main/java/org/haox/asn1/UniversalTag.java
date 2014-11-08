package org.haox.asn1;

public enum UniversalTag
{
    UNKNOWN             (-1),
    CHOICE              (-2), // Only for internal using
    BOOLEAN             (0x01),
    INTEGER             (0x02),
    BIT_STRING          (0x03),
    OCTET_STRING        (0x04),
    NULL                 (0x05),
    OBJECT_IDENTIFIER   (0x06),
    EXTERNAL             (0x08),
    REAL                  (0x09),
    ENUMERATED          (0x0a),
    SEQUENCE            (0x10),
    SEQUENCE_OF         (0x10),
    SET                  (0x11),
    SET_OF               (0x11),
    NUMERIC_STRING      (0x12),
    PRINTABLE_STRING    (0x13),
    T61_STRING          (0x14),
    VIDEOTEX_STRING     (0x15),
    IA5_STRING          (0x16),
    UTC_TIME            (0x17),
    GENERALIZED_TIME    (0x18),
    GRAPHIC_STRING      (0x19),
    VISIBLE_STRING      (0x1a),
    GENERAL_STRING      (0x1b),
    UNIVERSAL_STRING    (0x1c),
    BMP_STRING          (0x1e),
    UTF8_STRING         (0x0c);

    private int value;

    private UniversalTag(int value) {
        this.value = value;
    }

    public int getValue() {
        return value;
    }

    public static UniversalTag fromValue(int value) {
        for (UniversalTag e : values()) {
            if (e.getValue() == value) {
                return (UniversalTag) e;
            }
        }

        return UNKNOWN;
    }
}
