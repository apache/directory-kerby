package org.haox.kerb.base;

public enum TransitedEncodingType {
    UNKNOWN(-1),
    NULL(0),
    DOMAIN_X500_COMPRESS(1);

    private final int value;

    private TransitedEncodingType(int value) {
        this.value = value;
    }
}
