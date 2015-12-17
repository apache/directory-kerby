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
package org.apache.kerby.cms.type;

import org.apache.kerby.asn1.Asn1FieldInfo;
import org.apache.kerby.asn1.EnumType;
import org.apache.kerby.asn1.type.Asn1Any;
import org.apache.kerby.asn1.type.Asn1BitString;
import org.apache.kerby.asn1.type.Asn1ObjectIdentifier;
import org.apache.kerby.asn1.type.Asn1SequenceType;

import static org.apache.kerby.cms.type.OtherRecipientInfo.MyEnum.*;

/**
 * OtherRecipientInfo ::= SEQUENCE {
 *   oriType OBJECT IDENTIFIER,
 *   oriValue ANY DEFINED BY oriType }
 */
public class OtherRecipientInfo extends Asn1SequenceType {
    protected enum MyEnum implements EnumType {
        ORI_TYPE,
        ORI_VALUE;

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
            new Asn1FieldInfo(ORI_TYPE, Asn1ObjectIdentifier.class),
            new Asn1FieldInfo(ORI_VALUE, Asn1Any.class)
    };

    public OtherRecipientInfo() {
        super(fieldInfos);
    }

    public Asn1ObjectIdentifier getOriType() {
        return getFieldAs(ORI_TYPE, Asn1ObjectIdentifier.class);
    }

    public void setOriType(Asn1ObjectIdentifier oriType) {
        setFieldAs(ORI_TYPE, oriType);
    }

    public Asn1BitString getPublicKey() {
        return getFieldAs(ORI_VALUE, Asn1BitString.class);
    }

    public void setOriValue(Asn1BitString oriValue) {
        setFieldAs(ORI_VALUE, oriValue);
    }
}
