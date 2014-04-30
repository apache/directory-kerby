package org.haox.kerb.spec.type;

import org.haox.asn1.type.Asn1SequenceOf;
import org.haox.asn1.type.Asn1String;
import org.haox.asn1.type.Asn1Type;

import java.util.ArrayList;
import java.util.List;

public class KrbSequenceOfType<T extends Asn1Type> extends Asn1SequenceOf<T> {
    public List<String> getAsStrings() {
        List<T> elements = getElements();
        List<String> results = new ArrayList<String>();
        for (T ele : elements) {
            if (ele instanceof Asn1String) {
                results.add(((Asn1String) ele).getValue());
            }
            throw new RuntimeException("The targeted field type isn't of string");
        }
        return results;
    }
}
