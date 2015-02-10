/**
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *  
 *    http://www.apache.org/licenses/LICENSE-2.0
 *  
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License. 
 *  
 */
package org.apache.kerby.kerberos.kerb.identity;

import java.util.*;

public class Identity {
    private String name;
    private final Map<String, Attribute> attributes;

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
            throw new RuntimeException("Not a simple attribute");
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
