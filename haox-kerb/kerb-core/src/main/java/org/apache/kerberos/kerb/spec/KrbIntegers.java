package org.apache.kerberos.kerb.spec;

import org.apache.haox.asn1.type.Asn1Integer;

import java.util.ArrayList;
import java.util.List;

public class KrbIntegers extends KrbSequenceOfType<Asn1Integer> {

    public KrbIntegers() {
        super();
    }

    public KrbIntegers(List<Integer> values) {
        super();
        setValues(values);
    }

    public void setValues(List<Integer> values) {
        clear();
        if (values != null) {
            for (Integer value : values) {
                addElement(new Asn1Integer(value));
            }
        }
    }

    public List<Integer> getValues() {
        List<Integer> results = new ArrayList<Integer>();
        for (Asn1Integer value : getElements()) {
            results.add(value.getValue());
        }
        return results;
    }
}
