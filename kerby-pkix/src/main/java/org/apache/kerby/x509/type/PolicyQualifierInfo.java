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
import org.apache.kerby.asn1.type.Asn1Any;
import org.apache.kerby.asn1.type.Asn1SequenceType;
import org.apache.kerby.asn1.type.Asn1Type;

/**
 * 
 * <pre>
 *   PolicyQualifierInfo ::= SEQUENCE {
 *       policyQualifierId  PolicyQualifierId,
 *       qualifier          ANY DEFINED BY policyQualifierId
 *   }
 *
 *  PolicyQualifierId ::= OBJECT IDENTIFIER ( id-qt-cps | id-qt-unotice )
 * </pre>
 */
public class PolicyQualifierInfo extends Asn1SequenceType {
    protected enum PolicyQualifierInfoField implements EnumType {
        POLICY_QUALIFIER_ID,
        QUALIFIER;

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
        new Asn1FieldInfo(PolicyQualifierInfoField.POLICY_QUALIFIER_ID, PolicyQualifierId.class),
        new Asn1FieldInfo(PolicyQualifierInfoField.QUALIFIER, Asn1Any.class)
    };

    public PolicyQualifierInfo() {
        super(fieldInfos);
    }

    public PolicyQualifierId getPolicyQualifierId() {
        return getFieldAs(PolicyQualifierInfoField.POLICY_QUALIFIER_ID, PolicyQualifierId.class);
    }

    public void setPolicyQualifierId(PolicyQualifierId policyQualifierId) {
        setFieldAs(PolicyQualifierInfoField.POLICY_QUALIFIER_ID, policyQualifierId);
    }

    public <T extends Asn1Type> T getQualifierAs(Class<T> t) {
        return getFieldAsAny(PolicyQualifierInfoField.QUALIFIER, t);
    }

    public void setQualifier(Asn1Type qualifier) {
        setFieldAsAny(PolicyQualifierInfoField.QUALIFIER, qualifier);
    }
}
