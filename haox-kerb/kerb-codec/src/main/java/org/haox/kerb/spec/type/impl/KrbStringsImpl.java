package org.haox.kerb.spec.type.impl;

import org.haox.kerb.codec.AbstractSequenceOfType;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.KrbTypes;
import org.haox.kerb.spec.type.KrbString;
import org.haox.kerb.spec.type.KrbStrings;
import org.haox.kerb.spec.type.KrbType;

import java.util.ArrayList;
import java.util.List;

public class KrbStringsImpl extends AbstractSequenceOfType implements KrbStrings {

    public List<String> getValues() {
        List<KrbString> values = this.getElementsAs(KrbString.class);
        List<String> results = new ArrayList<String>();
        if (values != null) {
            for (KrbString ks : values) {
                results.add(ks.getValue());
            }
        }

        return results;
    }

    public void setValues(List<String> values) throws KrbException {
        elements.clear();
        if (values != null) {
            for (String value : values) {
                elements.add(KrbTypes.makeString(value));
            }
        }
    }

    @Override
    public Class<? extends KrbType> getElementType() {
        return ElementType;
    }
}
