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
import org.apache.kerby.asn1.type.Asn1ObjectIdentifier;
import org.apache.kerby.asn1.type.Asn1OctetString;
import org.apache.kerby.asn1.type.Asn1SequenceType;

import static org.apache.kerby.cms.type.EncryptedContentInfo.MyEnum.*;

/**
 * EncryptedContentInfo ::= SEQUENCE {
 *   contentType ContentType,
 *   contentEncryptionAlgorithm ContentEncryptionAlgorithmIdentifier,
 *   encryptedContent [0] IMPLICIT EncryptedContent OPTIONAL }
 *
 * ContentType ::= OBJECT IDENTIFIER
 *
 * EncryptedContent ::= OCTET STRING
 */
public class EncryptedContentInfo extends Asn1SequenceType {
    protected enum MyEnum implements EnumType {
        CONTENT_TYPE,
        CONTENT_ENCRYPTION_ALGORITHM,
        ENCRYPTED_CONTENT;

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
            new Asn1FieldInfo(CONTENT_TYPE, Asn1ObjectIdentifier.class),
            new Asn1FieldInfo(CONTENT_ENCRYPTION_ALGORITHM, ContentEncryptionAlgorithmIdentifier.class),
            new ImplicitField(ENCRYPTED_CONTENT, 0, Asn1OctetString.class)
    };

    public EncryptedContentInfo() {
        super(fieldInfos);
    }

    public Asn1ObjectIdentifier getContentType() {
        return getFieldAs(CONTENT_TYPE, Asn1ObjectIdentifier.class);
    }

    public void setContentType(Asn1ObjectIdentifier contentType) {
        setFieldAs(CONTENT_TYPE, contentType);
    }

    public ContentEncryptionAlgorithmIdentifier getContentEncryptionAlgorithmIdentifier() {
        return getFieldAs(CONTENT_ENCRYPTION_ALGORITHM, ContentEncryptionAlgorithmIdentifier.class);
    }

    public void setContentEncryptionAlgorithmIdentifier(ContentEncryptionAlgorithmIdentifier
                                                                contentEncryptionAlgorithmIdentifier) {
        setFieldAs(CONTENT_ENCRYPTION_ALGORITHM, contentEncryptionAlgorithmIdentifier);
    }

    public Asn1OctetString getEncryptedContent() {
        return getFieldAs(ENCRYPTED_CONTENT, Asn1OctetString.class);
    }

    public void setEncryptedContent(Asn1OctetString encryptedContent) {
        setFieldAs(ENCRYPTED_CONTENT, encryptedContent);
    }
}
