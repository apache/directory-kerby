package org.haox.kerb.spec.type;

import org.haox.asn1.type.SequenceOfType;

import java.util.List;

public class KerberosStrings extends SequenceOfType<KerberosString> {
    public KerberosStrings(List<String> strings) {
        super();
        setValues(strings);
    }

    public void setValues(List<String> values) {
        clear();
        if (values != null) {
            for (String value : values) {
                add(new KerberosString(value));
            }
        }
    }
}
