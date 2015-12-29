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
import org.apache.kerby.asn1.type.Asn1GeneralizedTime;
import org.apache.kerby.asn1.type.Asn1SequenceType;

/**
 * <pre>
 *    PrivateKeyUsagePeriod ::= SEQUENCE {
 *      notBefore       [0]     GeneralizedTime OPTIONAL,
 *      notAfter        [1]     GeneralizedTime OPTIONAL
 *    }
 * </pre>
 */
public class PrivateKeyUsagePeriod extends Asn1SequenceType {
    protected enum PrivateKeyUsagePeriodField implements EnumType {
        NOT_BEFORE,
        NOT_AFTER;

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
        new ExplicitField(PrivateKeyUsagePeriodField.NOT_BEFORE, Asn1GeneralizedTime.class),
        new ExplicitField(PrivateKeyUsagePeriodField.NOT_AFTER, Asn1GeneralizedTime.class)
    };

    public PrivateKeyUsagePeriod() {
        super(fieldInfos);
    }

    public Asn1GeneralizedTime getNotBeforeTime() {
        return getFieldAs(PrivateKeyUsagePeriodField.NOT_BEFORE, Asn1GeneralizedTime.class);
    }

    public void setNotBeforeTime(Asn1GeneralizedTime notBeforeTime) {
        setFieldAs(PrivateKeyUsagePeriodField.NOT_BEFORE, notBeforeTime);
    }

    public Asn1GeneralizedTime getNotAfterTime() {
        return getFieldAs(PrivateKeyUsagePeriodField.NOT_AFTER, Asn1GeneralizedTime.class);
    }

    public void setNotAfterTime(Asn1GeneralizedTime notAfterTime) {
        setFieldAs(PrivateKeyUsagePeriodField.NOT_AFTER, notAfterTime);
    }
}
