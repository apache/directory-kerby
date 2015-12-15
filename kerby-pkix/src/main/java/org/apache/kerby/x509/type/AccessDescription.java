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

import static org.apache.kerby.x509.type.AccessDescription.MyEnum.ACCESS_LOCATION;
import static org.apache.kerby.x509.type.AccessDescription.MyEnum.ACCESS_METHOD;

/**
 *
 * <pre>
 * AccessDescription  ::=  SEQUENCE {
 *       accessMethod          OBJECT IDENTIFIER,
 *       accessLocation        GeneralName
 *  }
 * </pre>
 */
public class AccessDescription extends Asn1SequenceType {
    protected enum MyEnum implements EnumType {
        ACCESS_METHOD,
        ACCESS_LOCATION;

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
        new Asn1FieldInfo(ACCESS_METHOD, Asn1ObjectIdentifier.class),
        new Asn1FieldInfo(ACCESS_LOCATION, GeneralName.class)
    };

    public AccessDescription() {
        super(fieldInfos);
    }

    public Asn1ObjectIdentifier getAccessMethod() {
        return getFieldAs(ACCESS_METHOD, Asn1ObjectIdentifier.class);
    }

    public void setAccessMethod(Asn1ObjectIdentifier accessMethod) {
        setFieldAs(ACCESS_METHOD, accessMethod);
    }

    public GeneralName getAccessLocation() {
        return getFieldAs(ACCESS_LOCATION, GeneralName.class);
    }

    public void setAccessLocation(GeneralName accessLocation) {
        setFieldAs(ACCESS_LOCATION, accessLocation);
    }
}
