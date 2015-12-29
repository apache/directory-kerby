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
package org.apache.kerby.x509.type;

import org.apache.kerby.asn1.Asn1FieldInfo;
import org.apache.kerby.asn1.EnumType;
import org.apache.kerby.asn1.type.Asn1ObjectIdentifier;
import org.apache.kerby.asn1.type.Asn1SequenceType;

/**
 * <pre>
 * Attribute ::= SEQUENCE {
 *     attrType OBJECT IDENTIFIER,
 *     attrValues SET OF AttributeValue
 * }
 *
 * AttributeValue ::= ANY
 *
 * </pre>
 */
public class Attribute extends Asn1SequenceType {
    protected enum AttributeField implements EnumType {
        ATTR_TYPE,
        ATTR_VALUES;

        @Override
        public int getValue() {
            return ordinal();
        }

        @Override
        public String getName() {
            return name();
        }
    }

    static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[] {
        new Asn1FieldInfo(AttributeField.ATTR_TYPE, Asn1ObjectIdentifier.class),
        new Asn1FieldInfo(AttributeField.ATTR_VALUES, AttributeValues.class)
    };

    public Attribute() {
        super(fieldInfos);
    }

    public Asn1ObjectIdentifier getAttrType() {
        return getFieldAs(AttributeField.ATTR_TYPE, Asn1ObjectIdentifier.class);
    }

    public void setAttrType(Asn1ObjectIdentifier attrType) {
        setFieldAs(AttributeField.ATTR_TYPE, attrType);
    }

    public AttributeValues getAttrValues() {
        return getFieldAs(AttributeField.ATTR_VALUES, AttributeValues.class);
    }

    public void setAttrValues(AttributeValues attrValues) {
        setFieldAs(AttributeField.ATTR_VALUES, attrValues);
    }
}
