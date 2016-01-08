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
 *
 * <pre>
 *
 * SignerInfo ::= SEQUENCE {
 *     version            CMSVersion,
 *     sid                SignerIdentifier,
 *     digestAlgorithm    DigestAlgorithmIdentifier,
 *     signedAttrs        [0] IMPLICIT SignedAttributes OPTIONAL,
 *     signatureAlgorithm SignatureAlgorithmIdentifier,
 *     signature          SignatureValue,
 *     unsignedAttrs      [1] IMPLICIT UnsignedAttributes OPTIONAL
 * }
 *
 * </pre>
 */
public class SignerInfo extends Asn1SequenceType {
    protected enum SignerInfoField implements EnumType {
        CMS_VERSION,
        SID,
        DIGEST_ALGORITHM,
        SIGNED_ATTRS,
        SIGNATURE_ALGORITHMS,
        SIGNATURE,
        UNSIGNED_ATTRS;

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
        new Asn1FieldInfo(SignerInfoField.CMS_VERSION, CmsVersion.class),
        new Asn1FieldInfo(SignerInfoField.SID, SignerIdentifier.class),
        new Asn1FieldInfo(SignerInfoField.DIGEST_ALGORITHM, DigestAlgorithmIdentifier.class),
        new ImplicitField(SignerInfoField.SIGNED_ATTRS, 0, SignedAttributes.class),
        new Asn1FieldInfo(SignerInfoField.SIGNATURE_ALGORITHMS, SignatureAlgorithmIdentifier.class),
        new Asn1FieldInfo(SignerInfoField.SIGNATURE, SignatureValue.class),
        new ImplicitField(SignerInfoField.UNSIGNED_ATTRS, 1, UnsignedAttributes.class)
    };

    public SignerInfo() {
        super(fieldInfos);
    }

    public int getCmsVersion() {
        return getFieldAsInteger(SignerInfoField.CMS_VERSION);
    }

    public void setCmsVersion(int version) {
        setFieldAsInt(SignerInfoField.CMS_VERSION, version);
    }

    public SignerIdentifier getSignerIdentifier() {
        return getFieldAs(SignerInfoField.SID, SignerIdentifier.class);
    }

    public void setSignerIdentifier(SignerIdentifier signerIdentifier) {
        setFieldAs(SignerInfoField.SID, signerIdentifier);
    }

    public DigestAlgorithmIdentifier getDigestAlgorithmIdentifier() {
        return getFieldAs(SignerInfoField.DIGEST_ALGORITHM, DigestAlgorithmIdentifier.class);
    }

    public void setDigestAlgorithmIdentifier(DigestAlgorithmIdentifier digestAlgorithmIdentifier) {
        setFieldAs(SignerInfoField.DIGEST_ALGORITHM, digestAlgorithmIdentifier);
    }

    public SignedAttributes getSignedAttributes() {
        return getFieldAs(SignerInfoField.SIGNED_ATTRS, SignedAttributes.class);
    }

    public void setSignedAttributes(SignedAttributes signedAttributes) {
        setFieldAs(SignerInfoField.SIGNED_ATTRS, signedAttributes);
    }

    public SignatureAlgorithmIdentifier getSignatureAlgorithmIdentifier() {
        return getFieldAs(SignerInfoField.SIGNATURE_ALGORITHMS, SignatureAlgorithmIdentifier.class);
    }

    public void setSignatureAlgorithmIdentifier(SignatureAlgorithmIdentifier signatureAlgorithmIdentifier) {
        setFieldAs(SignerInfoField.SIGNATURE_ALGORITHMS, signatureAlgorithmIdentifier);
    }

    public SignatureValue getSignatureValue() {
        return getFieldAs(SignerInfoField.SIGNATURE, SignatureValue.class);
    }

    public void setSignatureValue(SignatureValue signatureValue) {
        setFieldAs(SignerInfoField.SIGNATURE, signatureValue);
    }

    public UnsignedAttributes getUnsignedAttributes() {
        return getFieldAs(SignerInfoField.UNSIGNED_ATTRS, UnsignedAttributes.class);
    }

    public void setUnsignedAttributes(UnsignedAttributes unsignedAttributes) {
        setFieldAs(SignerInfoField.UNSIGNED_ATTRS, unsignedAttributes);
    }
}
