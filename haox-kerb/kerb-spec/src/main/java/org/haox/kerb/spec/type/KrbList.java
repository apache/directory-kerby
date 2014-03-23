package org.haox.kerb.spec.type;

import org.haox.kerb.spec.KrbException;

import java.util.List;

public interface KrbList<T extends KrbType> extends SequenceOfType {
    public List<T> getValues() throws KrbException;
    public void setValues(List<T> values) throws KrbException;
    public void addValue(T value) throws KrbException;
}
