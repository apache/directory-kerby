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

import org.apache.kerby.asn1.*;
import org.apache.kerby.asn1.type.*;

import static org.apache.kerby.x509.type.OtherName.MyEnum.*;

/**
 * <pre>
 * OtherName ::= SEQUENCE {
 *      type-id    OBJECT IDENTIFIER,
 *      value      [0] EXPLICIT ANY DEFINED BY type-id
 * }
 *
 * </pre>
 */
public class OtherName extends Asn1SequenceType {
    protected enum MyEnum implements EnumType {
        TYPE_ID,
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

    static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[] {
            new Asn1FieldInfo(TYPE_ID, Asn1ObjectIdentifier.class),
            new ExplicitField(VALUE, 0, Asn1Any.class)
    };

    public OtherName() {
        super(fieldInfos);
    }

    public Asn1ObjectIdentifier getTypeId() {
        return getFieldAs(TYPE_ID, Asn1ObjectIdentifier.class);
    }

    public void setTypeId(Asn1ObjectIdentifier algorithm) {
        setFieldAs(TYPE_ID, algorithm);
    }

    public <T extends Asn1Type> T getOtherNameValueAs(Class<T> t) {
        return getFieldAsAny(VALUE, t);
    }

    public void setOtherNameValue(Asn1Type value) {
        setFieldAsAny(VALUE, value);
    }
}
