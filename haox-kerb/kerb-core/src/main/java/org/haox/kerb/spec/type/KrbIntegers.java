package org.haox.kerb.spec.type;

import org.haox.asn1.type.Asn1Integer;
import org.haox.asn1.type.SequenceOfType;

import java.util.List;

public class KrbIntegers extends SequenceOfType<Asn1Integer> {
    public KrbIntegers(List<Integer> values) {
        super();
        setValues(values);
    }

    public void setValues(List<Integer> values) {
        clear();
        if (values != null) {
            for (Integer value : values) {
                add(new Asn1Integer(value));
            }
        }
    }
}
