package org.haox.kerb.spec.type;

public interface SequenceOfType extends KrbType {
    public Class<? extends KrbType> getElementType();
}
