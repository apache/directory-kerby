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
 * RecipientEncryptedKey ::= SEQUENCE {
 *   rid KeyAgreeRecipientIdentifier,
 *   encryptedKey EncryptedKey }
 */
public class RecipientEncryptedKey extends Asn1SequenceType {
    protected enum RecipientEncryptedKeyField implements EnumType {
        RID,
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
            new Asn1FieldInfo(RecipientEncryptedKeyField.RID, KeyAgreeRecipientIdentifier.class),
            new Asn1FieldInfo(RecipientEncryptedKeyField.ENCRYPTED_KEY, EncryptedKey.class)
    };

    public RecipientEncryptedKey() {
        super(fieldInfos);
    }

    public KeyAgreeRecipientIdentifier getRid() {
        return getFieldAs(RecipientEncryptedKeyField.RID, KeyAgreeRecipientIdentifier.class);
    }

    public void setRid(KeyAgreeRecipientIdentifier rid) {
        setFieldAs(RecipientEncryptedKeyField.RID, rid);
    }

    public EncryptedKey getEncryptedKey() {
        return getFieldAs(RecipientEncryptedKeyField.ENCRYPTED_KEY, EncryptedKey.class);
    }

    public void setEncryptedKey(EncryptedKey encryptedKey) {
        setFieldAs(RecipientEncryptedKeyField.ENCRYPTED_KEY, encryptedKey);
    }
}
