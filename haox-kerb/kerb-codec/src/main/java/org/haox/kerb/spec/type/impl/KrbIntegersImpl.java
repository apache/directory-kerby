package org.haox.kerb.spec.type.impl;

import org.haox.kerb.codec.AbstractSequenceOfType;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.KrbTypes;
import org.haox.kerb.spec.type.KrbInteger;
import org.haox.kerb.spec.type.KrbIntegers;
import org.haox.kerb.spec.type.KrbType;

import java.util.ArrayList;
import java.util.List;

public class KrbIntegersImpl extends AbstractSequenceOfType implements KrbIntegers {

    public List<Integer> getValues() {
        List<KrbInteger> values = this.getElementsAs(KrbInteger.class);
        List<Integer> results = new ArrayList<Integer>();
        if (values != null) {
            for (KrbInteger ks : values) {
                results.add(ks.getValue().intValue());
            }
        }

        return results;
    }

    public void setValues(List<Integer> values) throws KrbException {
        elements.clear();
        if (values != null) {
            for (Integer value : values) {
                elements.add(KrbTypes.makeInteger(value));
            }
        }
    }

    @Override
    public Class<? extends KrbType> getElementType() {
        return ElementType;
    }
}
