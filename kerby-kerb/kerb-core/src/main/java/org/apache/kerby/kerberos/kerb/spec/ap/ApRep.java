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
package org.apache.kerby.kerberos.kerb.spec.ap;

import org.apache.kerby.asn1.type.Asn1FieldInfo;
import org.apache.kerby.asn1.type.Asn1Integer;
import org.apache.kerby.kerberos.kerb.spec.common.KrbMessage;
import org.apache.kerby.kerberos.kerb.spec.common.EncryptedData;
import org.apache.kerby.kerberos.kerb.spec.common.KrbMessageType;

/**
 AP-REP          ::= [APPLICATION 15] SEQUENCE {
 pvno            [0] INTEGER (5),
 msg-type        [1] INTEGER (15),
 enc-part        [2] EncryptedData -- EncAPRepPart
 }
 */
public class ApRep extends KrbMessage {
    private static int ENC_PART = 2;

    static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[] {
            new Asn1FieldInfo(PVNO, 0, Asn1Integer.class),
            new Asn1FieldInfo(MSG_TYPE, 1, Asn1Integer.class),
            new Asn1FieldInfo(ENC_PART, 2, EncryptedData.class)
    };

    public ApRep() {
        super(KrbMessageType.AP_REP, fieldInfos);
    }

    private EncAPRepPart encRepPart;

    public EncAPRepPart getEncRepPart() {
        return encRepPart;
    }

    public void setEncRepPart(EncAPRepPart encRepPart) {
        this.encRepPart = encRepPart;
    }

    public EncryptedData getEncryptedEncPart() {
        return getFieldAs(ENC_PART, EncryptedData.class);
    }

    public void setEncryptedEncPart(EncryptedData encryptedEncPart) {
        setFieldAs(ENC_PART, encryptedEncPart);
    }
}
