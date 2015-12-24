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
import org.apache.kerby.kerberos.kerb.type.KerberosString;
import org.apache.kerby.kerberos.kerb.type.KerberosTime;
import org.apache.kerby.kerberos.kerb.type.KrbAppSequenceType;
import org.apache.kerby.kerberos.kerb.type.ad.AuthorizationData;
import org.apache.kerby.kerberos.kerb.type.base.EncryptionKey;
import org.apache.kerby.kerberos.kerb.type.base.HostAddresses;
import org.apache.kerby.kerberos.kerb.type.base.PrincipalName;
import org.apache.kerby.kerberos.kerb.type.base.TransitedEncoding;

/**
 -- Encrypted part of ticket
 EncTicketPart   ::= [APPLICATION 3] SEQUENCE {
 flags                   [0] TicketFlags,
 key                     [1] EncryptionKey,
 crealm                  [2] Realm,
 cname                   [3] PrincipalName,
 transited               [4] TransitedEncoding,
 authtime                [5] KerberosTime,
 starttime               [6] KerberosTime OPTIONAL,
 endtime                 [7] KerberosTime,
 renew-till              [8] KerberosTime OPTIONAL,
 caddr                   [9] HostAddresses OPTIONAL,
 authorization-data      [10] AuthorizationData OPTIONAL
 }
 */
public class EncTicketPart extends KrbAppSequenceType {
    public static final int TAG = 3;

    protected enum EncTicketPartField implements EnumType {
        FLAGS,
        KEY,
        CREALM,
        CNAME,
        TRANSITED,
        AUTHTIME,
        STARTTIME,
        ENDTIME,
        RENEW_TILL,
        CADDR,
        AUTHORIZATION_DATA;

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
            new ExplicitField(EncTicketPartField.FLAGS, TicketFlags.class),
            new ExplicitField(EncTicketPartField.KEY, EncryptionKey.class),
            new ExplicitField(EncTicketPartField.CREALM, KerberosString.class),
            new ExplicitField(EncTicketPartField.CNAME, PrincipalName.class),
            new ExplicitField(EncTicketPartField.TRANSITED, TransitedEncoding.class),
            new ExplicitField(EncTicketPartField.AUTHTIME, KerberosTime.class),
            new ExplicitField(EncTicketPartField.STARTTIME, KerberosTime.class),
            new ExplicitField(EncTicketPartField.ENDTIME, KerberosTime.class),
            new ExplicitField(EncTicketPartField.RENEW_TILL, KerberosTime.class),
            new ExplicitField(EncTicketPartField.CADDR, HostAddresses.class),
            new ExplicitField(EncTicketPartField.AUTHORIZATION_DATA, AuthorizationData.class)
    };

    public EncTicketPart() {
        super(TAG, fieldInfos);
    }

    public TicketFlags getFlags() {
        return getFieldAs(EncTicketPartField.FLAGS, TicketFlags.class);
    }

    public void setFlags(TicketFlags flags) {
        setFieldAs(EncTicketPartField.FLAGS, flags);
    }

    public EncryptionKey getKey() {
        return getFieldAs(EncTicketPartField.KEY, EncryptionKey.class);
    }

    public void setKey(EncryptionKey key) {
        setFieldAs(EncTicketPartField.KEY, key);
    }

    public String getCrealm() {
        return getFieldAsString(EncTicketPartField.CREALM);
    }

    public void setCrealm(String crealm) {
        setFieldAsString(EncTicketPartField.CREALM, crealm);
    }

    public PrincipalName getCname() {
        return getFieldAs(EncTicketPartField.CNAME, PrincipalName.class);
    }

    public void setCname(PrincipalName cname) {
        setFieldAs(EncTicketPartField.CNAME, cname);
    }

    public TransitedEncoding getTransited() {
        return getFieldAs(EncTicketPartField.TRANSITED, TransitedEncoding.class);
    }

    public void setTransited(TransitedEncoding transited) {
        setFieldAs(EncTicketPartField.TRANSITED, transited);
    }

    public KerberosTime getAuthTime() {
        return getFieldAs(EncTicketPartField.AUTHTIME, KerberosTime.class);
    }

    public void setAuthTime(KerberosTime authTime) {
        setFieldAs(EncTicketPartField.AUTHTIME, authTime);
    }

    public KerberosTime getStartTime() {
        return getFieldAs(EncTicketPartField.STARTTIME, KerberosTime.class);
    }

    public void setStartTime(KerberosTime startTime) {
        setFieldAs(EncTicketPartField.STARTTIME, startTime);
    }

    public KerberosTime getEndTime() {
        return getFieldAs(EncTicketPartField.ENDTIME, KerberosTime.class);
    }

    public void setEndTime(KerberosTime endTime) {
        setFieldAs(EncTicketPartField.ENDTIME, endTime);
    }

    public KerberosTime getRenewtill() {
        return getFieldAs(EncTicketPartField.RENEW_TILL, KerberosTime.class);
    }

    public void setRenewtill(KerberosTime renewtill) {
        setFieldAs(EncTicketPartField.RENEW_TILL, renewtill);
    }

    public HostAddresses getClientAddresses() {
        return getFieldAs(EncTicketPartField.CADDR, HostAddresses.class);
    }

    public void setClientAddresses(HostAddresses clientAddresses) {
        setFieldAs(EncTicketPartField.CADDR, clientAddresses);
    }

    public AuthorizationData getAuthorizationData() {
        return getFieldAs(EncTicketPartField.AUTHORIZATION_DATA, AuthorizationData.class);
    }

    public void setAuthorizationData(AuthorizationData authorizationData) {
        setFieldAs(EncTicketPartField.AUTHORIZATION_DATA, authorizationData);
    }
}
