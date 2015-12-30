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
import org.apache.kerby.asn1.type.Asn1SequenceType;

/**
 *
 * <pre>
 *       CertificatePair ::= SEQUENCE {
 *         forward        [0]    Certificate OPTIONAL,
 *         reverse        [1]    Certificate OPTIONAL,
 *             -- at least one of the pair shall be present --
 *       }
 * </pre>
 */
public class CertificatePair extends Asn1SequenceType {
    protected enum CertificatePairField implements EnumType {
        FORWARD,
        REVERSE;

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
        new ExplicitField(CertificatePairField.FORWARD, Certificate.class),
        new ExplicitField(CertificatePairField.REVERSE, Certificate.class)
    };

    public CertificatePair() {
        super(fieldInfos);
    }

    public Certificate getForward() {
        return getFieldAs(CertificatePairField.FORWARD, Certificate.class);
    }

    public void setForward(Certificate forward) {
        setFieldAs(CertificatePairField.FORWARD, forward);
    }

    public Certificate getReverse() {
        return getFieldAs(CertificatePairField.REVERSE, Certificate.class);
    }

    public void setReverse(Certificate reverse) {
        setFieldAs(CertificatePairField.REVERSE, reverse);
    }
}
