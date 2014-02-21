package org.haox.kerb.decoding.pac;

public class PacSidAttributes {

    private PacSid id;
    private int attributes;

    public PacSidAttributes(PacSid id, int attributes) {
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
