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
import org.apache.kerby.asn1.ExplicitField;
import org.apache.kerby.asn1.type.Asn1Integer;
import org.apache.kerby.asn1.type.Asn1SequenceType;

/**
 * Ref. RFC 5280
 * <pre>
 * id-ce-policyConstraints OBJECT IDENTIFIER ::=  { id-ce 36 }
 *
 * PolicyConstraints ::= SEQUENCE {
 *      requireExplicitPolicy           [0] SkipCerts OPTIONAL,
 *      inhibitPolicyMapping            [1] SkipCerts OPTIONAL }
 *
 * SkipCerts ::= INTEGER (0..MAX)
 * </pre>
 */
public class PolicyConstraints extends Asn1SequenceType {
    protected enum PolicyConstraintsField implements EnumType {
        REQUIRE_EXPLICIT_POLICY,
        INHIBIT_POLICY_MAPPING;

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
        new ExplicitField(PolicyConstraintsField.REQUIRE_EXPLICIT_POLICY, Asn1Integer.class),
        new ExplicitField(PolicyConstraintsField.INHIBIT_POLICY_MAPPING, Asn1Integer.class)
    };

    public PolicyConstraints() {
        super(fieldInfos);
    }

    public Asn1Integer getRequireExplicitPolicy() {
        return getFieldAs(PolicyConstraintsField.REQUIRE_EXPLICIT_POLICY, Asn1Integer.class);
    }

    public void setRequireExplicitPolicy(Asn1Integer requireExplicitPolicy) {
        setFieldAs(PolicyConstraintsField.REQUIRE_EXPLICIT_POLICY, requireExplicitPolicy);
    }

    public Asn1Integer getInhibitPolicyMapping() {
        return getFieldAs(PolicyConstraintsField.INHIBIT_POLICY_MAPPING, Asn1Integer.class);
    }

    public void setInhibitPolicyMapping(Asn1Integer inhibitPolicyMapping) {
        setFieldAs(PolicyConstraintsField.INHIBIT_POLICY_MAPPING, inhibitPolicyMapping);
    }
}
