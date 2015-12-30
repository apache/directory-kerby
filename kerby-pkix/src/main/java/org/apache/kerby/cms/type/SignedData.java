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
import org.apache.kerby.asn1.type.Asn1SequenceType;

/**
 * Ref. RFC 5652
 * <pre>
 * SignedData ::= SEQUENCE {
 *     version CMSVersion,
 *     digestAlgorithms DigestAlgorithmIdentifiers,
 *     encapContentInfo EncapsulatedContentInfo,
 *     certificates [0] IMPLICIT CertificateSet OPTIONAL,
 *     crls [1] IMPLICIT RevocationInfoChoices OPTIONAL,
 *     signerInfos SignerInfos
 *   }
 * </pre>
 *
 */
public class SignedData extends Asn1SequenceType {
    protected enum SignedDataField implements EnumType {
        CMS_VERSION,
        DIGEST_ALGORITHMS,
        ENCAP_CONTENT_INFO,
        CERTIFICATES,
        CRLS,
        SIGNER_INFOS;

        @Override
        public int getValue() {
            return ordinal();
        }

        @Override
        public String getName() {
            return name();
        }
    }

    static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[]{
        new Asn1FieldInfo(SignedDataField.CMS_VERSION, CmsVersion.class),
        new Asn1FieldInfo(SignedDataField.DIGEST_ALGORITHMS, DigestAlgorithmIdentifiers.class),
        new Asn1FieldInfo(SignedDataField.ENCAP_CONTENT_INFO, EncapsulatedContentInfo.class),
        new ImplicitField(SignedDataField.CERTIFICATES, 0, CertificateSet.class),
        new ImplicitField(SignedDataField.CRLS, 1, RevocationInfoChoices.class),
        new Asn1FieldInfo(SignedDataField.SIGNER_INFOS, SignerInfos.class)
    };

    public SignedData() {
        super(fieldInfos);
    }

    public int getVersion() {
        return getFieldAsInteger(SignedDataField.CMS_VERSION);
    }

    public void setVersion(int version) {
        setFieldAsInt(SignedDataField.CMS_VERSION, version);
    }

    public DigestAlgorithmIdentifiers getDigestAlgorithms() {
        return getFieldAs(SignedDataField.DIGEST_ALGORITHMS, DigestAlgorithmIdentifiers.class);
    }

    public void setDigestAlgorithms(DigestAlgorithmIdentifiers digestAlgorithms) {
        setFieldAs(SignedDataField.DIGEST_ALGORITHMS, digestAlgorithms);
    }

    public EncapsulatedContentInfo getEncapContentInfo() {
        return getFieldAs(SignedDataField.ENCAP_CONTENT_INFO, EncapsulatedContentInfo.class);
    }

    public void setEncapContentInfo(EncapsulatedContentInfo contentInfo) {
        setFieldAs(SignedDataField.ENCAP_CONTENT_INFO, contentInfo);
    }

    public CertificateSet getCertificates() {
        return getFieldAs(SignedDataField.CERTIFICATES, CertificateSet.class);
    }

    public void setCertificates(CertificateSet certificates) {
        setFieldAs(SignedDataField.CERTIFICATES, certificates);
    }

    public RevocationInfoChoices getCrls() {
        return getFieldAs(SignedDataField.CRLS, RevocationInfoChoices.class);
    }

    public void setCrls(RevocationInfoChoices crls) {
        setFieldAs(SignedDataField.CRLS, crls);
    }

    public SignerInfos getSignerInfos() {
        return getFieldAs(SignedDataField.SIGNER_INFOS, SignerInfos.class);
    }

    public void setSignerInfos(SignerInfos signerInfos) {
        setFieldAs(SignedDataField.SIGNER_INFOS, signerInfos);
    }

    /**
     * Check whether signed of data, true if the SignerInfos are not null
     * @return boolean
     */
    public boolean isSigned() {
        if (getSignerInfos().getElements().size() == 0) {
            return false;
        } else {
            return true;
        }
    }
}
