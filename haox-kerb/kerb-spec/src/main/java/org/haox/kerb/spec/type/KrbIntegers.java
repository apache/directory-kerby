package org.haox.kerb.spec.type;

import org.haox.kerb.spec.KrbException;

import java.util.List;

public interface KrbIntegers extends SequenceOfType {
    public static Class<? extends KrbType> ElementType = KrbInteger.class;

    public List<Integer> getValues();

    public void setValues(List<Integer> values) throws KrbException;
}
