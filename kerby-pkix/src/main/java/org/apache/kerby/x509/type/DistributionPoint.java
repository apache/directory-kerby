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
 * DistributionPoint ::= SEQUENCE {
 *      distributionPoint [0] DistributionPointName OPTIONAL,
 *      reasons           [1] ReasonFlags OPTIONAL,
 *      cRLIssuer         [2] GeneralNames OPTIONAL
 * }
 * </pre>
 */
public class DistributionPoint extends Asn1SequenceType {
    protected enum DistributionPointField implements EnumType {
        DISTRIBUTION_POINT,
        REASONS,
        CRL_ISSUER;

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
        new ExplicitField(DistributionPointField.DISTRIBUTION_POINT, DistributionPointName.class),
        new ExplicitField(DistributionPointField.REASONS, ReasonFlags.class),
        new ExplicitField(DistributionPointField.CRL_ISSUER, GeneralNames.class)
    };

    public DistributionPoint() {
        super(fieldInfos);
    }

    public DistributionPointName getDistributionPoint() {
        return getFieldAs(DistributionPointField.DISTRIBUTION_POINT, DistributionPointName.class);
    }

    public void setDistributionPoint(DistributionPointName distributionPoint) {
        setFieldAs(DistributionPointField.DISTRIBUTION_POINT, distributionPoint);
    }

    public ReasonFlags getReasons() {
        return getFieldAs(DistributionPointField.REASONS, ReasonFlags.class);
    }

    public void setReasons(ReasonFlags reasons) {
        setFieldAs(DistributionPointField.REASONS, reasons);
    }

    public GeneralNames getCRLIssuer() {
        return getFieldAs(DistributionPointField.CRL_ISSUER, GeneralNames.class);
    }

    public void setCRLIssuer(GeneralNames crlIssuer) {
        setFieldAs(DistributionPointField.CRL_ISSUER, crlIssuer);
    }
}
