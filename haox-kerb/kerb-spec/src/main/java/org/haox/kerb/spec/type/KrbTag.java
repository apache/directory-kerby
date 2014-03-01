package org.haox.kerb.spec.type;

public interface KrbTag {
    public int getValue();
    public int getIndex();
    public Class<? extends KrbType> getType();
}
