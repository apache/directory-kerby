package org.haox.kerb.spec.type;

import org.haox.kerb.spec.KrbException;

import java.util.List;

public interface KrbStrings extends SequenceOfType {
    public static Class<? extends KrbType> ElementType = KrbString.class;

    public List<String> getValues();

    public void setValues(List<String> values) throws KrbException;
}
