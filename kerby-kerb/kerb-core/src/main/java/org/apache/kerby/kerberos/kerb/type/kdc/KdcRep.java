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
package org.apache.kerby.kerberos.kerb.type.kdc;

import org.apache.kerby.asn1.Asn1FieldInfo;
import org.apache.kerby.asn1.EnumType;
import org.apache.kerby.asn1.ExplicitField;
import org.apache.kerby.asn1.type.Asn1Integer;
import org.apache.kerby.kerberos.kerb.type.KerberosString;
import org.apache.kerby.kerberos.kerb.type.base.EncryptedData;
import org.apache.kerby.kerberos.kerb.type.base.KrbMessage;
import org.apache.kerby.kerberos.kerb.type.base.KrbMessageType;
import org.apache.kerby.kerberos.kerb.type.base.PrincipalName;
import org.apache.kerby.kerberos.kerb.type.pa.PaData;
import org.apache.kerby.kerberos.kerb.type.ticket.Ticket;

/**
 KDC-REP         ::= SEQUENCE {
 pvno            [0] INTEGER (5),
 msg-type        [1] INTEGER (11 -- AS -- | 13 -- TGS --),
 padata          [2] SEQUENCE OF PA-DATA OPTIONAL
 -- NOTE: not empty --,
 crealm          [3] Realm,
 cname           [4] PrincipalName,
 ticket          [5] Ticket,
 enc-part        [6] EncryptedData
 -- EncASRepPart or EncTGSRepPart,
 -- as appropriate
 }
 */
public class KdcRep extends KrbMessage {
    protected enum KdcRepField implements EnumType {
        PVNO,
        MSG_TYPE,
        PADATA,
        CREALM,
        CNAME,
        TICKET,
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
            new ExplicitField(KdcRepField.PVNO, Asn1Integer.class),
            new ExplicitField(KdcRepField.MSG_TYPE, Asn1Integer.class),
            new ExplicitField(KdcRepField.PADATA, PaData.class),
            new ExplicitField(KdcRepField.CREALM, KerberosString.class),
            new ExplicitField(KdcRepField.CNAME, PrincipalName.class),
            new ExplicitField(KdcRepField.TICKET, Ticket.class),
            new ExplicitField(KdcRepField.ENC_PART, EncryptedData.class)
    };

    private EncKdcRepPart encPart;

    public KdcRep(KrbMessageType msgType) {
        super(msgType, fieldInfos);
    }

    public PaData getPaData() {
        return getFieldAs(KdcRepField.PADATA, PaData.class);
    }

    public void setPaData(PaData paData) {
        setFieldAs(KdcRepField.PADATA, paData);
    }

    public PrincipalName getCname() {
        return getFieldAs(KdcRepField.CNAME, PrincipalName.class);
    }

    public void setCname(PrincipalName sname) {
        setFieldAs(KdcRepField.CNAME, sname);
    }

    public String getCrealm() {
        return getFieldAsString(KdcRepField.CREALM);
    }

    public void setCrealm(String realm) {
        setFieldAs(KdcRepField.CREALM, new KerberosString(realm));
    }

    public Ticket getTicket() {
        return getFieldAs(KdcRepField.TICKET, Ticket.class);
    }

    public void setTicket(Ticket ticket) {
        setFieldAs(KdcRepField.TICKET, ticket);
    }

    public EncryptedData getEncryptedEncPart() {
        return getFieldAs(KdcRepField.ENC_PART, EncryptedData.class);
    }

    public void setEncryptedEncPart(EncryptedData encryptedEncPart) {
        setFieldAs(KdcRepField.ENC_PART, encryptedEncPart);
    }

    public EncKdcRepPart getEncPart() {
        return encPart;
    }

    public void setEncPart(EncKdcRepPart encPart) {
        this.encPart = encPart;
    }
}
