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

import org.apache.kerby.asn1.type.Asn1Choice;
import org.apache.kerby.asn1.type.Asn1FieldInfo;
import org.apache.kerby.asn1.type.ImplicitField;

/**
 * CertificateChoices ::= CHOICE {
 *   certificate Certificate,
 *   extendedCertificate [0] IMPLICIT ExtendedCertificate,  -- Obsolete
 *   v1AttrCert [1] IMPLICIT AttributeCertificateV1,        -- Obsolete
 *   v2AttrCert [2] IMPLICIT AttributeCertificateV2,
 *   other [3] IMPLICIT OtherCertificateFormat }
 */
public class CertificateChoices extends Asn1Choice {

    private static final int CERTIFICATE = 0;
    private static final int EXTENDED_CERTIFICATE = 1;
    private static final int V1_ATTR_CERT = 2;
    private static final int V2_ATTR_CERT = 3;
    private static final int OTHER = 4;

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
        return getFieldAs(CERTIFICATE, Certificate.class);
    }

    public void setCertificate(Certificate certificate) {
        setFieldAs(CERTIFICATE, certificate);
    }

    public ExtendedCertificate getExtendedCertificate() {
        return getFieldAs(EXTENDED_CERTIFICATE, ExtendedCertificate.class);
    }

    public void setExtendedCertificate(ExtendedCertificate extendedCertificate) {
        setFieldAs(EXTENDED_CERTIFICATE, extendedCertificate);
    }

    public AttributeCertificateV1 getV1AttrCert() {
        return getFieldAs(V1_ATTR_CERT, AttributeCertificateV1.class);
    }

    public void setV1AttrCert(AttributeCertificateV1 v1AttrCert) {
        setFieldAs(V1_ATTR_CERT, v1AttrCert);
    }

    public AttributeCertificateV2 getV2AttrCert() {
        return getFieldAs(V2_ATTR_CERT, AttributeCertificateV2.class);
    }

    public void setV2AttrCert(AttributeCertificateV2 v2AttrCert) {
        setFieldAs(V2_ATTR_CERT, v2AttrCert);
    }

    public OtherCertificateFormat getOther() {
        return getFieldAs(OTHER, OtherCertificateFormat.class);
    }

    public void setOther(OtherCertificateFormat other) {
        setFieldAs(OTHER, other);
    }
}
