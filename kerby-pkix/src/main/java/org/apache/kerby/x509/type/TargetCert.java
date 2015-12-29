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
 * TargetCert  ::= SEQUENCE {
 *   targetCertificate    IssuerSerial,
 *   targetName           GeneralName OPTIONAL,
 *   certDigestInfo       ObjectDigestInfo OPTIONAL
 * }
 */
public class TargetCert extends Asn1SequenceType {
    protected enum TargetCertField implements EnumType {
        TARGET_CERTIFICATE,
        TARGET_NAME,
        CERT_DIGEST_INFO;

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
            new Asn1FieldInfo(TargetCertField.TARGET_CERTIFICATE, IssuerSerial.class),
            new Asn1FieldInfo(TargetCertField.TARGET_NAME, GeneralName.class),
            new Asn1FieldInfo(TargetCertField.CERT_DIGEST_INFO, ObjectDigestInfo.class)
    };

    public TargetCert() {
        super(fieldInfos);
    }

    public IssuerSerial getTargetCertificate() {
        return getFieldAs(TargetCertField.TARGET_CERTIFICATE, IssuerSerial.class);
    }

    public void setTargetCertificate(IssuerSerial targetCertificate) {
        setFieldAs(TargetCertField.TARGET_CERTIFICATE, targetCertificate);
    }

    public GeneralName getTargetName() {
        return getFieldAs(TargetCertField.TARGET_NAME, GeneralName.class);
    }

    public void setTargetName(GeneralName targetName) {
        setFieldAs(TargetCertField.TARGET_NAME, targetName);
    }

    public ObjectDigestInfo getCertDigestInfo() {
        return getFieldAs(TargetCertField.CERT_DIGEST_INFO, ObjectDigestInfo.class);
    }

    public void setCerttDigestInfo(ObjectDigestInfo certDigestInfo) {
        setFieldAs(TargetCertField.CERT_DIGEST_INFO, certDigestInfo);
    }
}
