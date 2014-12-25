package org.haox.kerb.spec;

import java.util.List;

public class KerberosStrings extends KrbSequenceOfType<KerberosString> {

    public KerberosStrings() {
        super();
    }

    public KerberosStrings(List<String> strings) {
        super();
        setValues(strings);
    }

    public void setValues(List<String> values) {
        clear();
        if (values != null) {
            for (String value : values) {
                addElement(new KerberosString(value));
            }
        }
    }
}
