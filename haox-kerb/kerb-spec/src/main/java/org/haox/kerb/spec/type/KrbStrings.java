package org.haox.kerb.spec.type;

import org.haox.kerb.spec.KrbException;

import java.util.List;

public interface KrbStrings extends KrbType {
    public void addValue(String value) throws KrbException;

    public List<String> getValues();

    public void setValues(List<String> values) throws KrbException;
}
