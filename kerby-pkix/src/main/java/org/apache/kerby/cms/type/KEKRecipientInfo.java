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
import org.apache.kerby.asn1.type.Asn1SequenceType;

/**
 * KEKRecipientInfo ::= SEQUENCE {
 *   version CMSVersion,  -- always set to 4
 *   kekid KEKIdentifier,
 *   keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
 *   encryptedKey EncryptedKey }
 */
public class KEKRecipientInfo extends Asn1SequenceType {
    protected enum KEKRecipientInfoField implements EnumType {
        VERSION,
        KE_KID,
        KEY_ENCRYPTION_ALGORITHM,
        ENCRYPTED_KEY;

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
            new Asn1FieldInfo(KEKRecipientInfoField.VERSION, CmsVersion.class),
            new Asn1FieldInfo(KEKRecipientInfoField.KE_KID, KEKIdentifier.class),
            new Asn1FieldInfo(KEKRecipientInfoField.KEY_ENCRYPTION_ALGORITHM, KeyEncryptionAlgorithmIdentifier.class),
            new Asn1FieldInfo(KEKRecipientInfoField.ENCRYPTED_KEY, EncryptedKey.class)
    };

    public KEKRecipientInfo() {
        super(fieldInfos);
    }

    public CmsVersion getVersion() {
        return getFieldAs(KEKRecipientInfoField.VERSION, CmsVersion.class);
    }

    public void setVersion(CmsVersion version) {
        setFieldAs(KEKRecipientInfoField.VERSION, version);
    }

    public KEKIdentifier getKEKIdentifier() {
        return getFieldAs(KEKRecipientInfoField.KE_KID, KEKIdentifier.class);
    }

    public void setKEKIdentifier(KEKIdentifier kekIdentifier) {
        setFieldAs(KEKRecipientInfoField.KE_KID, kekIdentifier);
    }

    public KeyEncryptionAlgorithmIdentifier getKeyEncryptionAlgorithmIdentifier() {
        return getFieldAs(KEKRecipientInfoField.KEY_ENCRYPTION_ALGORITHM, KeyEncryptionAlgorithmIdentifier.class);
    }

    public void setKeyEncryptionAlgorithmIdentifier(KeyEncryptionAlgorithmIdentifier
                                                            keyEncryptionAlgorithmIdentifier) {
        setFieldAs(KEKRecipientInfoField.KEY_ENCRYPTION_ALGORITHM, keyEncryptionAlgorithmIdentifier);
    }

    public EncryptedKey getEncryptedKey() {
        return getFieldAs(KEKRecipientInfoField.ENCRYPTED_KEY, EncryptedKey.class);
    }

    public void setEncryptedKey(EncryptedKey encryptedKey) {
        setFieldAs(KEKRecipientInfoField.ENCRYPTED_KEY, encryptedKey);
    }
}
