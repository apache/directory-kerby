package org.haox.kerb.server.identity;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class ComplexAttribute extends Attribute {
    private List<String> values;

    public ComplexAttribute(String name) {
        super(name);
        this.values = new ArrayList<String>(1);
    }

    public List<String> getValues() {
        return Collections.unmodifiableList(values);
    }

    public void setValues(List<String> values) {
        this.values.clear();
        this.values.addAll(values);
    }
}
