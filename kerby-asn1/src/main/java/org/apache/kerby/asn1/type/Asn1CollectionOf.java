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
package org.apache.kerby.asn1.type;

import org.apache.kerby.asn1.Asn1Dumper;
import org.apache.kerby.asn1.Asn1Header;
import org.apache.kerby.asn1.UniversalTag;

import java.io.IOException;
import java.lang.reflect.ParameterizedType;
import java.util.ArrayList;
import java.util.List;

public abstract class Asn1CollectionOf<T extends Asn1Type>
    extends Asn1Collection {

    private List<T> elements = new ArrayList<>();

    public Asn1CollectionOf(UniversalTag universalTag) {
        super(universalTag);
    }

    @Override
    protected void decodeBody(Asn1Header header) throws IOException {
        super.decodeBody(header);

        decodeElements();
    }

    private void decodeElements() throws IOException {
        List<Asn1Type> items = getValue();
        for (Asn1Type itemObj : items) {
            if (itemObj instanceof Asn1Item) {
                Asn1Item item = (Asn1Item) itemObj;
                if (!item.isFullyDecoded()) {
                    Asn1Type tmpValue = createElement();
                    item.decodeValueWith(tmpValue);
                }
                itemObj = item.getValue();
            }
            elements.add((T) itemObj);
        }
    }

    public List<T> getElements() {
        return elements;
    }

    public void setElements(List<T> elements) {
        super.clear();

        for (T ele : elements) {
            addElement(ele);
        }
    }

    public void addElements(T ... elements) {
        for (T ele : elements) {
            addElement(ele);
        }
    }

    public void addElement(T element) {
        super.addItem(element);
        this.elements.add(element);
    }

    private Class<T> getElementType() {
        Class<T> elementType = (Class<T>) ((ParameterizedType)
            getClass().getGenericSuperclass()).getActualTypeArguments()[0];
        return elementType;
    }

    protected T createElement() throws IOException {
        Class<?> eleType = getElementType();
        try {
            T result = (T) eleType.newInstance();
            return result;
        } catch (Exception e) {
            throw new IOException("Failed to create element type", e);
        }
    }

    @Override
    public void dumpWith(Asn1Dumper dumper, int indents) {
        dumper.dumpTypeInfo(indents, getClass());

        for (Asn1Type aObj : elements) {
            dumper.dumpType(indents + 4, aObj).newLine();
        }
    }
}
