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
package org.apache.kerby.kerberos.kerb.spec.pa.pkinit;

import org.apache.kerby.asn1.type.Asn1FieldInfo;
import org.apache.kerby.kerberos.kerb.spec.KrbSequenceType;
import org.apache.kerby.kerberos.kerb.spec.common.CheckSum;
import org.apache.kerby.kerberos.kerb.spec.common.EncryptionKey;

/**
 ReplyKeyPack ::= SEQUENCE {
    replyKey                [0] EncryptionKey,
    asChecksum              [1] Checksum,
 }
 */
public class ReplyKeyPack extends KrbSequenceType {
    private static int REPLY_KEY = 0;
    private static int AS_CHECKSUM = 1;

    static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[] {
            new Asn1FieldInfo(REPLY_KEY, EncryptionKey.class),
            new Asn1FieldInfo(AS_CHECKSUM, CheckSum.class)
    };

    public ReplyKeyPack() {
        super(fieldInfos);
    }

    public EncryptionKey getReplyKey() {
        return getFieldAs(REPLY_KEY, EncryptionKey.class);
    }

    public void setReplyKey(EncryptionKey replyKey) {
        setFieldAs(REPLY_KEY, replyKey);
    }

    public CheckSum getAsChecksum() {
        return getFieldAs(AS_CHECKSUM, CheckSum.class);
    }

    public void setAsChecksum(CheckSum checkSum) {
        setFieldAs(AS_CHECKSUM, checkSum);
    }
}
