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

/*
 * <pre>
 * PolicyInformation ::= SEQUENCE {
 *      policyIdentifier   CertPolicyId,
 *      policyQualifiers   SEQUENCE SIZE (1..MAX) OF
 *              PolicyQualifierInfo OPTIONAL }
 * </pre>
 */
public class PolicyInformation extends Asn1SequenceType {
    private static final int POLICY_IDENTIFIER = 0;
    private static final int POLICY_QUALIFIERS = 1;

    static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[] {
        new Asn1FieldInfo(POLICY_IDENTIFIER, CertPolicyId.class),
        new Asn1FieldInfo(POLICY_QUALIFIERS, PolicyQualifierInfos.class)
    };

    public PolicyInformation() {
        super(fieldInfos);
    }

    public CertPolicyId getPolicyIdentifier() {
        return getFieldAs(POLICY_IDENTIFIER, CertPolicyId.class);
    }

    public void setPolicyIdentifier(CertPolicyId policyIdentifier) {
        setFieldAs(POLICY_IDENTIFIER, policyIdentifier);
    }
    
    public PolicyQualifierInfos getPolicyQualifiers() {
        return getFieldAs(POLICY_QUALIFIERS, PolicyQualifierInfos.class);
    }

    public void setPolicyQualifiers(PolicyQualifierInfos policyQualifiers) {
        setFieldAs(POLICY_QUALIFIERS, policyQualifiers);
    }
}
