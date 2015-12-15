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
package org.apache.kerby.kerberos.kerb.type.ap;

import org.apache.kerby.asn1.Asn1FieldInfo;
import org.apache.kerby.asn1.EnumType;
import org.apache.kerby.asn1.ExplicitField;
import org.apache.kerby.asn1.type.Asn1Integer;
import org.apache.kerby.kerberos.kerb.type.base.EncryptedData;
import org.apache.kerby.kerberos.kerb.type.base.KrbMessage;
import org.apache.kerby.kerberos.kerb.type.base.KrbMessageType;

import static org.apache.kerby.kerberos.kerb.type.ap.ApRep.MyEnum.ENC_PART;
import static org.apache.kerby.kerberos.kerb.type.ap.ApRep.MyEnum.MSG_TYPE;
import static org.apache.kerby.kerberos.kerb.type.ap.ApRep.MyEnum.PVNO;

/**
 AP-REP          ::= [APPLICATION 15] SEQUENCE {
 pvno            [0] INTEGER (5),
 msg-type        [1] INTEGER (15),
 enc-part        [2] EncryptedData -- EncAPRepPart
 }
 */
public class ApRep extends KrbMessage {
    protected enum MyEnum implements EnumType {
        PVNO,
        MSG_TYPE,
        ENC_PART;

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
            new ExplicitField(PVNO, 0, Asn1Integer.class),
            new ExplicitField(MSG_TYPE, 1, Asn1Integer.class),
            new ExplicitField(ENC_PART, 2, EncryptedData.class)
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
