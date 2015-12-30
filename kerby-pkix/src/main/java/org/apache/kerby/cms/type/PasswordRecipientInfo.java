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
import org.apache.kerby.asn1.type.Asn1SequenceType;

/**
 * PasswordRecipientInfo ::= SEQUENCE {
 *   version CMSVersion,   -- always set to 0
 *   keyDerivationAlgorithm [0] KeyDerivationAlgorithmIdentifier OPTIONAL,
 *   keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
 *   encryptedKey EncryptedKey }
 */
public class PasswordRecipientInfo extends Asn1SequenceType {
    protected enum PwdRInfoField implements EnumType {
        VERSION,
        KEY_DERIVATION_ALGORIGHM,
        KEY_ENCRYPTION_ALGORITHMS,
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
            new Asn1FieldInfo(PwdRInfoField.VERSION, CmsVersion.class),
            new ExplicitField(PwdRInfoField.KEY_DERIVATION_ALGORIGHM, 0, KeyDerivationAlgorithmIdentifier.class),
            new Asn1FieldInfo(PwdRInfoField.KEY_ENCRYPTION_ALGORITHMS, KeyEncryptionAlgorithmIdentifier.class),
            new Asn1FieldInfo(PwdRInfoField.ENCRYPTED_KEY, EncryptedKey.class)
    };

    public PasswordRecipientInfo() {
        super(fieldInfos);
    }

    public CmsVersion getVersion() {
        return getFieldAs(PwdRInfoField.VERSION, CmsVersion.class);
    }

    public void setVersion(CmsVersion version) {
        setFieldAs(PwdRInfoField.VERSION, version);
    }

    public KeyDerivationAlgorithmIdentifier getKeyDerivationAlgorithmIdentifier() {
        return getFieldAs(PwdRInfoField.KEY_DERIVATION_ALGORIGHM, KeyDerivationAlgorithmIdentifier.class);
    }

    public void setKeyDerivationAlgorithmIdentifier(KeyDerivationAlgorithmIdentifier
                                                            keyDerivationAlgorithmIdentifier) {
        setFieldAs(PwdRInfoField.KEY_DERIVATION_ALGORIGHM, keyDerivationAlgorithmIdentifier);
    }

    public KeyEncryptionAlgorithmIdentifier getKeyEncryptionAlgorithmIdentifier() {
        return getFieldAs(PwdRInfoField.KEY_ENCRYPTION_ALGORITHMS, KeyEncryptionAlgorithmIdentifier.class);
    }

    public void setKeyEncryptionAlgorithmIdentifier(KeyEncryptionAlgorithmIdentifier
                                                            keyEncryptionAlgorithmIdentifier) {
        setFieldAs(PwdRInfoField.KEY_ENCRYPTION_ALGORITHMS, keyEncryptionAlgorithmIdentifier);
    }

    public EncryptedKey getEncryptedKey() {
        return getFieldAs(PwdRInfoField.ENCRYPTED_KEY, EncryptedKey.class);
    }

    public void setEncryptedKey(EncryptedKey encryptedKey) {
        setFieldAs(PwdRInfoField.ENCRYPTED_KEY, encryptedKey);
    }
}
