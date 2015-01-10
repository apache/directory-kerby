package org.apache.kerberos.kerb.identity;

import java.util.*;

public class Identity {
    private String name;
    private Map<String, Attribute> attributes;

    public Identity(String name) {
        this.name = name;
        this.attributes = new HashMap<String, Attribute>();
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public void addAttribute(String name, String value) {
        attributes.put(name, new SimpleAttribute(name, value));
    }

    public void addAttribute(Attribute attribute) {
        attributes.put(attribute.getName(), attribute);
    }

    public Set<String> getAttributes() {
        return Collections.unmodifiableSet(attributes.keySet());
    }

    public String getSimpleAttribute(String name) {
        Attribute attr = attributes.get(name);
        if (! (attr instanceof SimpleAttribute)) {
            throw new RuntimeException("Not simple attribute");
        }
        return ((SimpleAttribute) attr).getValue();
    }

    public void setAttributes(List<Attribute> attributes) {
        this.attributes.clear();
        for (Attribute attr : attributes) {
            addAttribute(attr);
        }
    }
}
