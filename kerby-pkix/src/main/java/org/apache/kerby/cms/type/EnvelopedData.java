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

import static org.apache.kerby.cms.type.EnvelopedData.MyEnum.*;

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

    protected enum MyEnum implements EnumType {
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
            new Asn1FieldInfo(CMS_VERSION, CmsVersion.class),
            new ImplicitField(ORIGINATOR_INFO, 0, OriginatorInfo.class),
            new Asn1FieldInfo(RECIPIENT_INFOS, RecipientInfos.class),
            new Asn1FieldInfo(ENCRYPTED_CONTENT_INFO, EncryptedContentInfo.class),
            new ImplicitField(UNPROTECTED_ATTRS, 1, UnprotectedAttributes.class)
    };

    public EnvelopedData() {
        super(fieldInfos);
    }

    public CmsVersion getCmsVersion() {
        return getFieldAs(CMS_VERSION, CmsVersion.class);
    }

    public void setCmsVersion(CmsVersion cmsVersion) {
        setFieldAs(CMS_VERSION, cmsVersion);
    }

    public OriginatorInfo getOriginatorInfo() {
        return getFieldAs(ORIGINATOR_INFO, OriginatorInfo.class);
    }

    public void setOriginatorInfo(OriginatorInfo originatorInfo) {
        setFieldAs(ORIGINATOR_INFO, originatorInfo);
    }
    public RecipientInfos getRecipientInfos() {
        return getFieldAs(RECIPIENT_INFOS, RecipientInfos.class);
    }

    public void setRecipientInfos(RecipientInfos recipientInfos) {
        setFieldAs(RECIPIENT_INFOS, recipientInfos);
    }
    public EncryptedContentInfo getEncryptedContentInfo() {
        return getFieldAs(ENCRYPTED_CONTENT_INFO, EncryptedContentInfo.class);
    }

    public void setEncryptedContentInfo(EncryptedContentInfo encryptedContentInfo) {
        setFieldAs(ENCRYPTED_CONTENT_INFO, encryptedContentInfo);
    }
    public UnprotectedAttributes getUnprotectedAttributes() {
        return getFieldAs(UNPROTECTED_ATTRS, UnprotectedAttributes.class);
    }

    public void setUnprotectedAttributes(UnprotectedAttributes unprotectedAttributes) {
        setFieldAs(UNPROTECTED_ATTRS, unprotectedAttributes);
    }
}
