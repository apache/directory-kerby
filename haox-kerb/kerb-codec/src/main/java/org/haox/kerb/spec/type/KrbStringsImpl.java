package org.haox.kerb.spec.type;

import org.haox.kerb.codec.AbstractSequenceOfType;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.KrbTypes;

import java.util.ArrayList;
import java.util.List;

public class KrbStringsImpl extends AbstractSequenceOfType implements KrbStrings {
    public KrbStringsImpl() {
        super(KrbString.class);
    }

    public void addValue(String value) throws KrbException {
        this.addElement(KrbTypes.makeString(value));
    }

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
        if (values != null) {
            for (String value : values) {
                this.addValue(value);
            }
        }
    }
}
