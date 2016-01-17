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

import org.apache.kerby.asn1.Asn1Binder;
import org.apache.kerby.asn1.UniversalTag;
import org.apache.kerby.asn1.parse.Asn1ParseResult;

import java.io.IOException;
import java.lang.reflect.ParameterizedType;
import java.util.List;

public abstract class Asn1CollectionOf<T extends Asn1Type>
    extends Asn1Collection {

    public Asn1CollectionOf(UniversalTag universalTag) {
        super(universalTag);
    }

    @Override
    protected void decodeElements() throws IOException {
        for (Asn1ParseResult parsingItem : getContainer().getChildren()) {
            if (parsingItem.isEOC()) {
                continue;
            }

            Asn1Type tmpValue = createElement();
            Asn1Binder.bind(parsingItem, tmpValue);
            addItem(tmpValue);
        }
    }

    public List<T> getElements() {
        return (List<T>) getValue();
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
            throw new IOException("Failed to create element type, "
                + "no default constructor? " + eleType.getName(), e);
        }
    }
}
