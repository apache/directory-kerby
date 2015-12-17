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

import static org.apache.kerby.cms.type.KeyTransRecipientInfo.MyEnum.*;

/**
 * KeyTransRecipientInfo ::= SEQUENCE {
 *   version CMSVersion,  -- always set to 0 or 2
 *   rid RecipientIdentifier,
 *   keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
 *   encryptedKey EncryptedKey }
 */
public class KeyTransRecipientInfo extends Asn1SequenceType {
    protected enum MyEnum implements EnumType {
        VERSION,
        RID,
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
            new Asn1FieldInfo(VERSION, CmsVersion.class),
            new Asn1FieldInfo(RID, RecipientIdentifier.class),
            new Asn1FieldInfo(KEY_ENCRYPTION_ALGORITHM, KeyEncryptionAlgorithmIdentifier.class),
            new Asn1FieldInfo(ENCRYPTED_KEY, EncryptedKey.class)
    };

    public KeyTransRecipientInfo() {
        super(fieldInfos);
    }

    public CmsVersion getVersion() {
        return getFieldAs(VERSION, CmsVersion.class);
    }

    public void setVersion(CmsVersion version) {
        setFieldAs(VERSION, version);
    }

    public RecipientIdentifier getRid() {
        return getFieldAs(RID, RecipientIdentifier.class);
    }

    public void setRid(RecipientIdentifier rid) {
        setFieldAs(RID, rid);
    }

    public KeyEncryptionAlgorithmIdentifier getKeyEncryptionAlgorithmIdentifier() {
        return getFieldAs(KEY_ENCRYPTION_ALGORITHM, KeyEncryptionAlgorithmIdentifier.class);
    }

    public void setKeyEncryptionAlgorithmIdentifier(KeyEncryptionAlgorithmIdentifier
                                                            keyEncryptionAlgorithmIdentifier) {
        setFieldAs(KEY_ENCRYPTION_ALGORITHM, keyEncryptionAlgorithmIdentifier);
    }

    public EncryptedKey getEncryptedKey() {
        return getFieldAs(ENCRYPTED_KEY, EncryptedKey.class);
    }

    public void setEncryptedKey(EncryptedKey encryptedKey) {
        setFieldAs(ENCRYPTED_KEY, encryptedKey);
    }
}
