package org.haox.kerb.decoding.pac;

public class PacGroup {

    private PacSid id;
    private int attributes;

    public PacGroup(PacSid id, int attributes) {
        super();
        this.id = id;
        this.attributes = attributes;
    }

    public PacSid getId() {
        return id;
    }

    public int getAttributes() {
        return attributes;
    }

}
