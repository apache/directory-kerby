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
package org.apache.kerby.cms.type;

import org.apache.kerby.asn1.Asn1FieldInfo;
import org.apache.kerby.asn1.EnumType;
import org.apache.kerby.asn1.ImplicitField;
import org.apache.kerby.asn1.type.Asn1Choice;
import org.apache.kerby.x509.type.Certificate;

import static org.apache.kerby.cms.type.CertificateChoices.MyEnum.CERTIFICATE;
import static org.apache.kerby.cms.type.CertificateChoices.MyEnum.EXTENDED_CERTIFICATE;
import static org.apache.kerby.cms.type.CertificateChoices.MyEnum.OTHER;
import static org.apache.kerby.cms.type.CertificateChoices.MyEnum.V1_ATTR_CERT;
import static org.apache.kerby.cms.type.CertificateChoices.MyEnum.V2_ATTR_CERT;

/**
 * CertificateChoices ::= CHOICE {
 *   certificate Certificate,
 *   extendedCertificate [0] IMPLICIT ExtendedCertificate,  -- Obsolete
 *   v1AttrCert [1] IMPLICIT AttributeCertificateV1,        -- Obsolete
 *   v2AttrCert [2] IMPLICIT AttributeCertificateV2,
 *   other [3] IMPLICIT OtherCertificateFormat }
 */
@SuppressWarnings("PMD.TooManyStaticImports")
public class CertificateChoices extends Asn1Choice {
    protected enum MyEnum implements EnumType {
        CERTIFICATE,
        EXTENDED_CERTIFICATE,
        V1_ATTR_CERT,
        V2_ATTR_CERT,
        OTHER;

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
            new Asn1FieldInfo(CERTIFICATE, Certificate.class),
            new ImplicitField(EXTENDED_CERTIFICATE, 0, ExtendedCertificate.class),
            new ImplicitField(V1_ATTR_CERT, 1, AttributeCertificateV1.class),
            new ImplicitField(V2_ATTR_CERT, 2, AttributeCertificateV2.class),
            new ImplicitField(OTHER, 3, OtherCertificateFormat.class),
    };

    public CertificateChoices() {
        super(fieldInfos);
    }

    public Certificate getCertificate() {
        return getChoiceValueAs(CERTIFICATE, Certificate.class);
    }

    public void setCertificate(Certificate certificate) {
        setChoiceValue(CERTIFICATE, certificate);
    }

    public ExtendedCertificate getExtendedCertificate() {
        return getChoiceValueAs(EXTENDED_CERTIFICATE, ExtendedCertificate.class);
    }

    public void setExtendedCertificate(ExtendedCertificate extendedCertificate) {
        setChoiceValue(EXTENDED_CERTIFICATE, extendedCertificate);
    }

    public AttributeCertificateV1 getV1AttrCert() {
        return getChoiceValueAs(V1_ATTR_CERT, AttributeCertificateV1.class);
    }

    public void setV1AttrCert(AttributeCertificateV1 v1AttrCert) {
        setChoiceValue(V1_ATTR_CERT, v1AttrCert);
    }

    public AttributeCertificateV2 getV2AttrCert() {
        return getChoiceValueAs(V2_ATTR_CERT, AttributeCertificateV2.class);
    }

    public void setV2AttrCert(AttributeCertificateV2 v2AttrCert) {
        setChoiceValue(V2_ATTR_CERT, v2AttrCert);
    }

    public OtherCertificateFormat getOther() {
        return getChoiceValueAs(OTHER, OtherCertificateFormat.class);
    }

    public void setOther(OtherCertificateFormat other) {
        setChoiceValue(OTHER, other);
    }
}
