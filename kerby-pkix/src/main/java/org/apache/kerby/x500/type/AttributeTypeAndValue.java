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
package org.apache.kerby.x500.type;

import org.apache.kerby.asn1.Asn1FieldInfo;
import org.apache.kerby.asn1.EnumType;
import org.apache.kerby.asn1.type.Asn1Any;
import org.apache.kerby.asn1.type.Asn1ObjectIdentifier;
import org.apache.kerby.asn1.type.Asn1SequenceType;
import org.apache.kerby.asn1.type.Asn1Type;

/**
 * AttributeTypeAndValue ::= SEQUENCE {
 *     type  OBJECT IDENTIFIER,
 *     value ANY
 * }
 */
public class AttributeTypeAndValue extends Asn1SequenceType {
    protected enum AttributeTypeAndValueField implements EnumType {
        TYPE,
        VALUE;

        @Override
        public int getValue() {
            return ordinal();
        }

        @Override
        public String getName() {
            return name();
        }
    }

    static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[]{
            new Asn1FieldInfo(AttributeTypeAndValueField.TYPE, -1, Asn1ObjectIdentifier.class, true),
            new Asn1FieldInfo(AttributeTypeAndValueField.VALUE, -1, Asn1Any.class, true)
    };

    public AttributeTypeAndValue() {
        super(fieldInfos);
    }

    public Asn1ObjectIdentifier getType() {
        return getFieldAs(AttributeTypeAndValueField.TYPE, Asn1ObjectIdentifier.class);
    }

    public void setType(Asn1ObjectIdentifier type) {
        setFieldAs(AttributeTypeAndValueField.TYPE, type);
    }

    public <T extends Asn1Type> T getAttributeValueAs(Class<T> t) {
        return getFieldAsAny(AttributeTypeAndValueField.VALUE, t);
    }

    public void setAttributeValue(Asn1Type value) {
        setFieldAsAny(AttributeTypeAndValueField.VALUE, value);
    }
}
