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
import org.apache.kerby.asn1.type.Asn1SequenceType;

/**
 * Ref. RFC 2459
 *
 * <pre>
 * SEQUENCE  {
 *   userCertificate         CertificateSerialNumber,
 *   revocationDate          Time,
 *   crlEntryExtensions      Extensions OPTIONAL
 *                                 -- if present, shall be v2
 * }
 * </pre>
 */
public class RevokedCertificate extends Asn1SequenceType {
    protected enum RevokedCertificateField implements EnumType {
        USER_CERTIFICATE,
        REVOCATION_DATA,
        CRL_ENTRY_EXTENSIONS;

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
        new Asn1FieldInfo(RevokedCertificateField.USER_CERTIFICATE, CertificateSerialNumber.class),
        new Asn1FieldInfo(RevokedCertificateField.REVOCATION_DATA, Time.class),
        new Asn1FieldInfo(RevokedCertificateField.CRL_ENTRY_EXTENSIONS, Extensions.class)
    };

    public RevokedCertificate() {
        super(fieldInfos);
    }

    public CertificateSerialNumber getUserCertificate() {
        return getFieldAs(RevokedCertificateField.USER_CERTIFICATE, CertificateSerialNumber.class);
    }

    public void setUserCertificate(CertificateSerialNumber userCertificate) {
        setFieldAs(RevokedCertificateField.USER_CERTIFICATE, userCertificate);
    }

    public Time getRevocationDate() {
        return getFieldAs(RevokedCertificateField.REVOCATION_DATA, Time.class);
    }

    public void setRevocationData(Time revocationData) {
        setFieldAs(RevokedCertificateField.REVOCATION_DATA, revocationData);
    }

    public Extensions getCrlEntryExtensions() {
        return getFieldAs(RevokedCertificateField.CRL_ENTRY_EXTENSIONS, Extensions.class);
    }

    public void setCrlEntryExtensions(Extensions crlEntryExtensions) {
        setFieldAs(RevokedCertificateField.CRL_ENTRY_EXTENSIONS, crlEntryExtensions);
    }
}
