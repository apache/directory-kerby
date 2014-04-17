package org.haox.kerb.spec.type;

import org.haox.kerb.codec.AbstractSequenceOfType;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.KrbTypes;
import org.haox.kerb.spec.type.KrbList;
import org.haox.kerb.spec.type.KrbString;
import org.haox.kerb.spec.type.KrbStrings;
import org.haox.kerb.spec.type.KrbType;

import java.util.ArrayList;
import java.util.List;

public class KrbListImpl<T extends KrbType> extends AbstractSequenceOfType implements KrbList<T> {

    public List<T> getValues() {
        return null;
    }

    public void setValues(List<T> values) throws KrbException {

    }

    @Override
    public void addValue(T value) throws KrbException {

    }

    @Override
    public Class<? extends KrbType> getElementType() {
        return null;
    }
}
