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
import org.apache.kerby.asn1.ExplicitField;
import org.apache.kerby.asn1.type.Asn1OctetString;
import org.apache.kerby.asn1.type.Asn1SequenceType;

/**
 * KeyAgreeRecipientInfo ::= SEQUENCE {
 *   version CMSVersion,  -- always set to 3
 *   originator [0] EXPLICIT OriginatorIdentifierOrKey,
 *   ukm [1] EXPLICIT UserKeyingMaterial OPTIONAL,
 *   keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
 *   recipientEncryptedKeys RecipientEncryptedKeys }
 *
 * UserKeyingMaterial ::= OCTET STRING
 */
public class KeyAgreeRecipientInfo extends Asn1SequenceType {
    protected enum KARInfoField implements EnumType {
        VERSION,
        ORIGINATOR,
        UKM,
        KEY_ENCRYPTION_ALGORITHM,
        RECIPIENT_ENCRYPTED_KEY;

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
            new Asn1FieldInfo(KARInfoField.VERSION, CmsVersion.class),
            new ExplicitField(KARInfoField.ORIGINATOR, 0, OriginatorIdentifierOrKey.class),
            new ExplicitField(KARInfoField.UKM, 1, Asn1OctetString.class),
            new Asn1FieldInfo(KARInfoField.KEY_ENCRYPTION_ALGORITHM, KeyEncryptionAlgorithmIdentifier.class),
            new Asn1FieldInfo(KARInfoField.RECIPIENT_ENCRYPTED_KEY, RecipientEncryptedKeys.class)
    };

    public KeyAgreeRecipientInfo() {
        super(fieldInfos);
    }

    public CmsVersion getVersion() {
        return getFieldAs(KARInfoField.VERSION, CmsVersion.class);
    }

    public void setVersion(CmsVersion version) {
        setFieldAs(KARInfoField.VERSION, version);
    }

    public OriginatorIdentifierOrKey getOriginator() {
        return getFieldAs(KARInfoField.ORIGINATOR, OriginatorIdentifierOrKey.class);
    }

    public void setOriginator(OriginatorIdentifierOrKey originator) {
        setFieldAs(KARInfoField.ORIGINATOR, originator);
    }

    public Asn1OctetString getUkm() {
        return getFieldAs(KARInfoField.UKM, Asn1OctetString.class);
    }

    public void setUkm(Asn1OctetString ukm) {
        setFieldAs(KARInfoField.UKM, ukm);
    }

    public KeyEncryptionAlgorithmIdentifier getKeyEncryptionAlgorithmIdentifier() {
        return getFieldAs(KARInfoField.KEY_ENCRYPTION_ALGORITHM, KeyEncryptionAlgorithmIdentifier.class);
    }

    public void setkeyEncryptionAlgorithmIdentifier(KeyEncryptionAlgorithmIdentifier
                                                            keyEncryptionAlgorithmIdentifier) {
        setFieldAs(KARInfoField.KEY_ENCRYPTION_ALGORITHM, keyEncryptionAlgorithmIdentifier);
    }

    public RecipientEncryptedKeys getRecipientEncryptedKeys() {
        return getFieldAs(KARInfoField.RECIPIENT_ENCRYPTED_KEY, RecipientEncryptedKeys.class);
    }

    public void setRecipientEncryptedKeys(RecipientEncryptedKeys recipientEncryptedKeys) {
        setFieldAs(KARInfoField.RECIPIENT_ENCRYPTED_KEY, recipientEncryptedKeys);
    }
}
