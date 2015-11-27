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

/**
 * Ref. RFC3280
 * <pre>
 *    PolicyMappings ::= SEQUENCE SIZE (1..MAX) OF SEQUENCE {
 *      issuerDomainPolicy      CertPolicyId,
 *      subjectDomainPolicy     CertPolicyId }
 * </pre>
 *
 */
public class PolicyMapping extends Asn1SequenceType {
    private static final int ISSUER_DOMAIN_POLICY = 0;
    private static final int SUBJECT_DOMAIN_POLICY = 1;

    static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[] {
        new Asn1FieldInfo(ISSUER_DOMAIN_POLICY, CertPolicyId.class),
        new Asn1FieldInfo(SUBJECT_DOMAIN_POLICY, CertPolicyId.class)
    };

    public PolicyMapping() {
        super(fieldInfos);
    }

    public CertPolicyId getIssuerDomainPolicy() {
        return  getFieldAs(ISSUER_DOMAIN_POLICY, CertPolicyId.class);
    }

    public void setIssuerDomainPolicy(CertPolicyId issuerDomainPolicy) {
        setFieldAs(ISSUER_DOMAIN_POLICY, issuerDomainPolicy);
    }

    public CertPolicyId getSubjectDomainPolicy() {
        return getFieldAs(SUBJECT_DOMAIN_POLICY, CertPolicyId.class);
    }

    public void setSubjectDomainPolicy(CertPolicyId subjectDomainPolicy) {
        setFieldAs(SUBJECT_DOMAIN_POLICY, subjectDomainPolicy);
    }
}
