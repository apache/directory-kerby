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

import org.apache.kerby.asn1.type.Asn1Any;
import org.apache.kerby.asn1.type.Asn1FieldInfo;
import org.apache.kerby.asn1.type.Asn1ObjectIdentifier;
import org.apache.kerby.asn1.type.Asn1SequenceType;
import org.apache.kerby.asn1.type.Asn1Type;
import org.apache.kerby.asn1.type.ExplicitField;

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
    private static final int TYPE_ID = 0;
    private static final int VALUE = 1;

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

    public Asn1Type getOtherNameValue() {
        return getFieldAsAny(VALUE);
    }

    public void setOtherNameValue(Asn1Type value) {
        setFieldAsAny(VALUE, value);
    }
}
