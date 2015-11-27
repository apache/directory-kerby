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

import org.apache.kerby.asn1.type.Asn1Boolean;
import org.apache.kerby.asn1.type.Asn1FieldInfo;
import org.apache.kerby.asn1.type.Asn1SequenceType;
import org.apache.kerby.asn1.type.ExplicitField;

/**
 * <pre>
 * IssuingDistributionPoint ::= SEQUENCE { 
 *   distributionPoint          [0] DistributionPointName OPTIONAL, 
 *   onlyContainsUserCerts      [1] BOOLEAN DEFAULT FALSE, 
 *   onlyContainsCACerts        [2] BOOLEAN DEFAULT FALSE, 
 *   onlySomeReasons            [3] ReasonFlags OPTIONAL, 
 *   indirectCRL                [4] BOOLEAN DEFAULT FALSE,
 *   onlyContainsAttributeCerts [5] BOOLEAN DEFAULT FALSE
 * }
 * </pre>
 */
public class IssuingDistributionPoint extends Asn1SequenceType {
    private static final int DISTRIBUTION_POINT = 0;
    private static final int ONLY_CONTAINS_USER_CERTS = 1;
    private static final int ONLY_CONTAINS_CA_CERTS = 2;
    private static final int ONLY_SOME_REASONS = 3;
    private static final int INDIRECT_CRL = 4;
    private static final int ONLY_CONTAINS_ATTRIBUTE_CERTS = 5;

    static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[] {
        new ExplicitField(DISTRIBUTION_POINT, DistributionPointName.class),
        new ExplicitField(ONLY_CONTAINS_USER_CERTS, Asn1Boolean.class),
        new ExplicitField(ONLY_CONTAINS_CA_CERTS, Asn1Boolean.class),
        new ExplicitField(ONLY_SOME_REASONS, ReasonFlags.class),
        new ExplicitField(INDIRECT_CRL, Asn1Boolean.class),
        new ExplicitField(ONLY_CONTAINS_ATTRIBUTE_CERTS, Asn1Boolean.class)
    };

    public IssuingDistributionPoint() {
        super(fieldInfos);
    }

    public DistributionPointName getDistributionPoint() {
        return getFieldAs(DISTRIBUTION_POINT, DistributionPointName.class);
    }

    public void setDistributionPoint(DistributionPointName distributionPoint) {
        setFieldAs(DISTRIBUTION_POINT, distributionPoint);
    }

    public boolean getOnlyContainsUserCerts() {
        return getFieldAs(ONLY_CONTAINS_USER_CERTS, Asn1Boolean.class).getValue();
    }

    public void setOnlyContainsUserCerts(boolean onlyContainsUserCerts) {
        setFieldAs(ONLY_CONTAINS_USER_CERTS, new Asn1Boolean(onlyContainsUserCerts));
    }

    public boolean getOnlyContainsCACerts() {
        return getFieldAs(ONLY_CONTAINS_CA_CERTS, Asn1Boolean.class).getValue();
    }

    public void setOnlyContainsCaCerts(boolean onlyContainsCaCerts) {
        setFieldAs(ONLY_CONTAINS_CA_CERTS, new Asn1Boolean(onlyContainsCaCerts));
    }

    public ReasonFlags getOnlySomeReasons() {
        return getFieldAs(ONLY_SOME_REASONS, ReasonFlags.class);
    }

    public void setOnlySomeReasons(ReasonFlags onlySomeReasons) {
        setFieldAs(ONLY_SOME_REASONS, onlySomeReasons);
    }

    public boolean getIndirectCRL() {
        return getFieldAs(INDIRECT_CRL, Asn1Boolean.class).getValue();
    }

    public void setIndirectCrl(boolean indirectCrl) {
        setFieldAs(INDIRECT_CRL, new Asn1Boolean(indirectCrl));
    }

    public boolean getOnlyContainsAttributeCerts() {
        return getFieldAs(ONLY_CONTAINS_ATTRIBUTE_CERTS, Asn1Boolean.class).getValue();
    }

    public void setOnlyContainsAttributeCerts(boolean onlyContainsAttributeCerts) {
        setFieldAs(ONLY_CONTAINS_ATTRIBUTE_CERTS, new Asn1Boolean(onlyContainsAttributeCerts));
    }
}
