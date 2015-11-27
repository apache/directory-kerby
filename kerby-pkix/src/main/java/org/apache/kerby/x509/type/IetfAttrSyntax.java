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

import org.apache.kerby.asn1.type.Asn1FieldInfo;
import org.apache.kerby.asn1.type.Asn1SequenceType;
import org.apache.kerby.asn1.type.ExplicitField;

/**
 * Ref. RFC3281
 * <pre>
 *
 *  IetfAttrSyntax ::= SEQUENCE {
 *    policyAuthority [0] GeneralNames OPTIONAL,
 *    values SEQUENCE OF CHOICE {
 *      octets OCTET STRING,
 *      oid OBJECT IDENTIFIER,
 *      string UTF8String
 *    }
 *  }
 *
 * </pre>
 */
public class IetfAttrSyntax extends Asn1SequenceType {
    public static final int POLICY_AUTHORITY = 0;
    public static final int VALUES = 1;

    static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[] {
        new ExplicitField(POLICY_AUTHORITY, GeneralNames.class),
        new Asn1FieldInfo(VALUES, IetfAttrSyntaxChoices.class)
    };

    public IetfAttrSyntax() {
        super(fieldInfos);
    }

    public GeneralNames getPolicyAuthority() {
        return getFieldAs(POLICY_AUTHORITY, GeneralNames.class);
    }

    public void setPolicyAuthority(GeneralNames policyAuthority) {
        setFieldAs(POLICY_AUTHORITY, policyAuthority);
    }

    public IetfAttrSyntaxChoices getValues() {
        return getFieldAs(VALUES, IetfAttrSyntaxChoices.class);
    }

    public void setValues(IetfAttrSyntaxChoices values) {
        setFieldAs(VALUES, values);
    }
}
