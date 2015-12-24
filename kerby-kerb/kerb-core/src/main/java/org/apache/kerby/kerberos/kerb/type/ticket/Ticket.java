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
package org.apache.kerby.kerberos.kerb.type.ticket;

import org.apache.kerby.asn1.Asn1FieldInfo;
import org.apache.kerby.asn1.EnumType;
import org.apache.kerby.asn1.ExplicitField;
import org.apache.kerby.asn1.type.Asn1Integer;
import org.apache.kerby.kerberos.kerb.KrbConstant;
import org.apache.kerby.kerberos.kerb.type.KerberosString;
import org.apache.kerby.kerberos.kerb.type.KrbAppSequenceType;
import org.apache.kerby.kerberos.kerb.type.base.EncryptedData;
import org.apache.kerby.kerberos.kerb.type.base.PrincipalName;

/**
 Ticket          ::= [APPLICATION 1] SEQUENCE {
 tkt-vno         [0] INTEGER (5),
 realm           [1] Realm,
 sname           [2] PrincipalName,
 enc-part        [3] EncryptedData -- EncTicketPart
 }
 */
public class Ticket extends KrbAppSequenceType {
    public static final int TKT_KVNO = KrbConstant.KRB_V5;
    public static final int TAG = 1;

    protected enum TicketField implements EnumType {
        TKT_VNO,
        REALM,
        SNAME,
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
            new ExplicitField(TicketField.TKT_VNO, 0, Asn1Integer.class),
            new ExplicitField(TicketField.REALM, 1, KerberosString.class),
            new ExplicitField(TicketField.SNAME, 2, PrincipalName.class),
            new ExplicitField(TicketField.ENC_PART, 3, EncryptedData.class)
    };

    public Ticket() {
        super(TAG, fieldInfos);
        setTktKvno(TKT_KVNO);
    }

    private EncTicketPart encPart;

    public int getTktvno() {
        return getFieldAsInt(TicketField.TKT_VNO);
    }

    public void setTktKvno(int kvno) {
        setFieldAsInt(TicketField.TKT_VNO, kvno);
    }
    public PrincipalName getSname() {
        return getFieldAs(TicketField.SNAME, PrincipalName.class);
    }

    public void setSname(PrincipalName sname) {
        setFieldAs(TicketField.SNAME, sname);
    }

    public String getRealm() {
        return getFieldAsString(TicketField.REALM);
    }

    public void setRealm(String realm) {
        setFieldAs(TicketField.REALM, new KerberosString(realm));
    }

    public EncryptedData getEncryptedEncPart() {
        return getFieldAs(TicketField.ENC_PART, EncryptedData.class);
    }

    public void setEncryptedEncPart(EncryptedData encryptedEncPart) {
        setFieldAs(TicketField.ENC_PART, encryptedEncPart);
    }

    public EncTicketPart getEncPart() {
        return encPart;
    }

    public void setEncPart(EncTicketPart encPart) {
        this.encPart = encPart;
    }
}
