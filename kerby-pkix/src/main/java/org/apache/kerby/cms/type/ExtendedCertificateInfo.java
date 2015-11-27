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

import org.apache.kerby.asn1.type.Asn1FieldInfo;
import org.apache.kerby.asn1.type.Asn1SequenceType;

/**
 * ExtendedCertificateInfo ::= SEQUENCE {
 *   version CMSVersion,
 *   certificate Certificate,
 *   attributes UnauthAttributes
 * }
 */
public class ExtendedCertificateInfo extends Asn1SequenceType {
    private static final int CMS_VERSION = 0;
    private static final int CERTIFICATE = 1;
    private static final int ATTRIBUTES = 2;

    static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[] {
            new Asn1FieldInfo(CMS_VERSION, CmsVersion.class),
            new Asn1FieldInfo(CERTIFICATE, SignatureAlgorithmIdentifier.class),
            new Asn1FieldInfo(ATTRIBUTES, Signature.class)
    };

    public ExtendedCertificateInfo() {
        super(fieldInfos);
    }

    public CmsVersion getCmsVersion() {
        return getFieldAs(CMS_VERSION, CmsVersion.class);
    }

    public void setCmsVersion(CmsVersion version) {
        setFieldAs(CMS_VERSION, version);
    }

    public SignatureAlgorithmIdentifier getCertificate() {
        return getFieldAs(CERTIFICATE, SignatureAlgorithmIdentifier.class);
    }

    public void setCertificate(SignatureAlgorithmIdentifier signatureAlgorithmIdentifier) {
        setFieldAs(CERTIFICATE, signatureAlgorithmIdentifier);
    }

    public Signature getAttributes() {
        return getFieldAs(ATTRIBUTES, Signature.class);
    }

    public void setAttributes(Signature signature) {
        setFieldAs(ATTRIBUTES, signature);
    }

}
