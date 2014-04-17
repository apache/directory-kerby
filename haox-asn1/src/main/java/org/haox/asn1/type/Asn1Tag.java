package org.haox.asn1.type;

public interface Asn1Tag {
    public int getValue();
    public int getIndex();
    public Class<? extends Asn1Type> getType();
}
