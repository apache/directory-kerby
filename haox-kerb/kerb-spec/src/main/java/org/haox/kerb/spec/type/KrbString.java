package org.haox.kerb.spec.type;

public class KrbString implements KrbType {
    private String value;

    public void setValue(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
