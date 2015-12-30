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
 * EnvelopedData ::= SEQUENCE {
 *   version CMSVersion,
 *   originatorInfo [0] IMPLICIT OriginatorInfo OPTIONAL,
 *   recipientInfos RecipientInfos,
 *   encryptedContentInfo EncryptedContentInfo,
 *   unprotectedAttrs [1] IMPLICIT UnprotectedAttributes OPTIONAL
 * }
 *
 * OriginatorInfo ::= SEQUENCE {
 *   certs [0] IMPLICIT CertificateSet OPTIONAL,
 *   crls [1] IMPLICIT RevocationInfoChoices OPTIONAL
 * }
 *
 * RecipientInfos ::= SET SIZE (1..MAX) OF RecipientInfo
 *
 * EncryptedContentInfo ::= SEQUENCE {
 *   contentType ContentType,
 *   contentEncryptionAlgorithm ContentEncryptionAlgorithmIdentifier,
 *   encryptedContent [0] IMPLICIT EncryptedContent OPTIONAL
 * }
 *
 * EncryptedContent ::= OCTET STRING
 *
 * UnprotectedAttributes ::= SET SIZE (1..MAX) OF Attribute
 */
public class EnvelopedData extends Asn1SequenceType {

    protected enum EnvelopedDataField implements EnumType {
        CMS_VERSION,
        ORIGINATOR_INFO,
        RECIPIENT_INFOS,
        ENCRYPTED_CONTENT_INFO,
        UNPROTECTED_ATTRS;

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
            new Asn1FieldInfo(EnvelopedDataField.CMS_VERSION, CmsVersion.class),
            new ImplicitField(EnvelopedDataField.ORIGINATOR_INFO, 0, OriginatorInfo.class),
            new Asn1FieldInfo(EnvelopedDataField.RECIPIENT_INFOS, RecipientInfos.class),
            new Asn1FieldInfo(EnvelopedDataField.ENCRYPTED_CONTENT_INFO, EncryptedContentInfo.class),
            new ImplicitField(EnvelopedDataField.UNPROTECTED_ATTRS, 1, UnprotectedAttributes.class)
    };

    public EnvelopedData() {
        super(fieldInfos);
    }

    public CmsVersion getCmsVersion() {
        return getFieldAs(EnvelopedDataField.CMS_VERSION, CmsVersion.class);
    }

    public void setCmsVersion(CmsVersion cmsVersion) {
        setFieldAs(EnvelopedDataField.CMS_VERSION, cmsVersion);
    }

    public OriginatorInfo getOriginatorInfo() {
        return getFieldAs(EnvelopedDataField.ORIGINATOR_INFO, OriginatorInfo.class);
    }

    public void setOriginatorInfo(OriginatorInfo originatorInfo) {
        setFieldAs(EnvelopedDataField.ORIGINATOR_INFO, originatorInfo);
    }
    public RecipientInfos getRecipientInfos() {
        return getFieldAs(EnvelopedDataField.RECIPIENT_INFOS, RecipientInfos.class);
    }

    public void setRecipientInfos(RecipientInfos recipientInfos) {
        setFieldAs(EnvelopedDataField.RECIPIENT_INFOS, recipientInfos);
    }
    public EncryptedContentInfo getEncryptedContentInfo() {
        return getFieldAs(EnvelopedDataField.ENCRYPTED_CONTENT_INFO, EncryptedContentInfo.class);
    }

    public void setEncryptedContentInfo(EncryptedContentInfo encryptedContentInfo) {
        setFieldAs(EnvelopedDataField.ENCRYPTED_CONTENT_INFO, encryptedContentInfo);
    }
    public UnprotectedAttributes getUnprotectedAttributes() {
        return getFieldAs(EnvelopedDataField.UNPROTECTED_ATTRS, UnprotectedAttributes.class);
    }

    public void setUnprotectedAttributes(UnprotectedAttributes unprotectedAttributes) {
        setFieldAs(EnvelopedDataField.UNPROTECTED_ATTRS, unprotectedAttributes);
    }
}
