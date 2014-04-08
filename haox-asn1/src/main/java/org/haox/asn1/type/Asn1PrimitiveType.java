package org.haox.asn1.type;

public interface Asn1PrimitiveType<T> extends Asn1Type {
    public T getValue();
}
