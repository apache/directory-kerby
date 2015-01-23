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
package org.apache.kerby.kerberos.kerb.spec.ticket;

import org.apache.kerby.asn1.type.Asn1FieldInfo;
import org.apache.kerby.asn1.type.Asn1Integer;
import org.apache.kerby.kerberos.kerb.KrbConstant;
import org.apache.kerby.kerberos.kerb.spec.KerberosString;
import org.apache.kerby.kerberos.kerb.spec.KrbAppSequenceType;
import org.apache.kerby.kerberos.kerb.spec.common.EncryptedData;
import org.apache.kerby.kerberos.kerb.spec.common.PrincipalName;

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

    private static int TKT_VNO = 0;
    private static int REALM = 1;
    private static int SNAME = 2;
    private static int ENC_PART = 3;

    static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[] {
            new Asn1FieldInfo(TKT_VNO, 0, Asn1Integer.class),
            new Asn1FieldInfo(REALM, 1, KerberosString.class),
            new Asn1FieldInfo(SNAME, 2, PrincipalName.class),
            new Asn1FieldInfo(ENC_PART, 3, EncryptedData.class)
    };

    public Ticket() {
        super(TAG, fieldInfos);
        setTktKvno(TKT_KVNO);
    }

    private EncTicketPart encPart;

    public int getTktvno() {
        return getFieldAsInt(TKT_VNO);
    }

    public void setTktKvno(int kvno) {
        setFieldAsInt(TKT_VNO, kvno);
    }
    public PrincipalName getSname() {
        return getFieldAs(SNAME, PrincipalName.class);
    }

    public void setSname(PrincipalName sname) {
        setFieldAs(SNAME, sname);
    }

    public String getRealm() {
        return getFieldAsString(REALM);
    }

    public void setRealm(String realm) {
        setFieldAs(REALM, new KerberosString(realm));
    }

    public EncryptedData getEncryptedEncPart() {
        return getFieldAs(ENC_PART, EncryptedData.class);
    }

    public void setEncryptedEncPart(EncryptedData encryptedEncPart) {
        setFieldAs(ENC_PART, encryptedEncPart);
    }

    public EncTicketPart getEncPart() {
        return encPart;
    }

    public void setEncPart(EncTicketPart encPart) {
        this.encPart = encPart;
    }
}
