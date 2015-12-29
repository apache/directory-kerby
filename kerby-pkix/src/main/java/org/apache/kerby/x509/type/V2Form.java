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
 * Produce an object suitable for an ASN1OutputStream.
 * <pre>
 *  V2Form ::= SEQUENCE {
 *       issuerName            GeneralNames  OPTIONAL,
 *       baseCertificateID     [0] IssuerSerial  OPTIONAL,
 *       objectDigestInfo      [1] ObjectDigestInfo  OPTIONAL
 *         -- issuerName MUST be present in this profile
 *         -- baseCertificateID and objectDigestInfo MUST NOT
 *         -- be present in this profile
 *  }
 * </pre>
 */
public class V2Form extends Asn1SequenceType {
    protected enum V2FormField implements EnumType {
        ISSUER_NAME,
        BASE_CERTIFICATE_ID,
        OBJECT_DIGEST_INFO;

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
        new Asn1FieldInfo(V2FormField.ISSUER_NAME, GeneralNames.class),
        new ExplicitField(V2FormField.BASE_CERTIFICATE_ID, 0, IssuerSerial.class),
        new ExplicitField(V2FormField.OBJECT_DIGEST_INFO, 1, ObjectDigestInfo.class)
    };

    public V2Form() {
        super(fieldInfos);
    }

    public GeneralNames getIssuerName() {
        return getFieldAs(V2FormField.ISSUER_NAME, GeneralNames.class);
    }

    public void setIssuerName(GeneralNames issuerName) {
        setFieldAs(V2FormField.ISSUER_NAME, issuerName);
    }

    public IssuerSerial getBaseCertificateID() {
        return getFieldAs(V2FormField.BASE_CERTIFICATE_ID, IssuerSerial.class);
    }

    public void setBaseCertificateId(IssuerSerial baseCertificateId) {
        setFieldAs(V2FormField.BASE_CERTIFICATE_ID, baseCertificateId);
    }

    public ObjectDigestInfo getObjectDigestInfo() {
        return getFieldAs(V2FormField.OBJECT_DIGEST_INFO, ObjectDigestInfo.class);
    }

    public void setObjectDigestInfo(ObjectDigestInfo objectDigestInfo) {
        setFieldAs(V2FormField.OBJECT_DIGEST_INFO, objectDigestInfo);
    }
}
