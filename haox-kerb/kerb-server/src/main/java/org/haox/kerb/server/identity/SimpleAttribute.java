package org.haox.kerb.server.identity;

public class SimpleAttribute extends Attribute {
    private String value;

    public SimpleAttribute(String name, String value) {
        super(name);
        this.value = value;
    }

    public String getValue() {
        return value;
    }

    public void setValue(String value) {
        this.value = value;
    }
}
