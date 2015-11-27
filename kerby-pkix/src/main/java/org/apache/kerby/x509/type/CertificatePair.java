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
    private static final int FORWARD = 0;
    private static final int REVERSE = 1;

    static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[] {
        new ExplicitField(FORWARD, Certificate.class),
        new ExplicitField(REVERSE, Certificate.class)
    };

    public CertificatePair() {
        super(fieldInfos);
    }

    public Certificate getForward() {
        return getFieldAs(FORWARD, Certificate.class);
    }

    public void setForward(Certificate forward) {
        setFieldAs(FORWARD, forward);
    }

    public Certificate getReverse() {
        return getFieldAs(REVERSE, Certificate.class);
    }

    public void setReverse(Certificate reverse) {
        setFieldAs(REVERSE, reverse);
    }
}
