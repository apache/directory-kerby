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

import static org.apache.kerby.kerberos.kerb.type.ticket.EncTicketPart.MyEnum.*;

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

    protected enum MyEnum implements EnumType {
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
            new ExplicitField(FLAGS, 0, TicketFlags.class),
            new ExplicitField(KEY, 1, EncryptionKey.class),
            new ExplicitField(CREALM, 2, KerberosString.class),
            new ExplicitField(CNAME, 3, PrincipalName.class),
            new ExplicitField(TRANSITED, 4, TransitedEncoding.class),
            new ExplicitField(AUTHTIME, 5, KerberosTime.class),
            new ExplicitField(STARTTIME, 6, KerberosTime.class),
            new ExplicitField(ENDTIME, 7, KerberosTime.class),
            new ExplicitField(ENDTIME, 8, KerberosTime.class),
            new ExplicitField(CADDR, 9, HostAddresses.class),
            new ExplicitField(AUTHORIZATION_DATA, 10, AuthorizationData.class)
    };

    public EncTicketPart() {
        super(TAG, fieldInfos);
    }

    public TicketFlags getFlags() {
        return getFieldAs(FLAGS, TicketFlags.class);
    }

    public void setFlags(TicketFlags flags) {
        setFieldAs(FLAGS, flags);
    }

    public EncryptionKey getKey() {
        return getFieldAs(KEY, EncryptionKey.class);
    }

    public void setKey(EncryptionKey key) {
        setFieldAs(KEY, key);
    }

    public String getCrealm() {
        return getFieldAsString(CREALM);
    }

    public void setCrealm(String crealm) {
        setFieldAsString(CREALM, crealm);
    }

    public PrincipalName getCname() {
        return getFieldAs(CNAME, PrincipalName.class);
    }

    public void setCname(PrincipalName cname) {
        setFieldAs(CNAME, cname);
    }

    public TransitedEncoding getTransited() {
        return getFieldAs(TRANSITED, TransitedEncoding.class);
    }

    public void setTransited(TransitedEncoding transited) {
        setFieldAs(TRANSITED, transited);
    }

    public KerberosTime getAuthTime() {
        return getFieldAs(AUTHTIME, KerberosTime.class);
    }

    public void setAuthTime(KerberosTime authTime) {
        setFieldAs(AUTHTIME, authTime);
    }

    public KerberosTime getStartTime() {
        return getFieldAs(STARTTIME, KerberosTime.class);
    }

    public void setStartTime(KerberosTime startTime) {
        setFieldAs(STARTTIME, startTime);
    }

    public KerberosTime getEndTime() {
        return getFieldAs(ENDTIME, KerberosTime.class);
    }

    public void setEndTime(KerberosTime endTime) {
        setFieldAs(ENDTIME, endTime);
    }

    public KerberosTime getRenewtill() {
        return getFieldAs(RENEW_TILL, KerberosTime.class);
    }

    public void setRenewtill(KerberosTime renewtill) {
        setFieldAs(RENEW_TILL, renewtill);
    }

    public HostAddresses getClientAddresses() {
        return getFieldAs(CADDR, HostAddresses.class);
    }

    public void setClientAddresses(HostAddresses clientAddresses) {
        setFieldAs(CADDR, clientAddresses);
    }

    public AuthorizationData getAuthorizationData() {
        return getFieldAs(AUTHORIZATION_DATA, AuthorizationData.class);
    }

    public void setAuthorizationData(AuthorizationData authorizationData) {
        setFieldAs(AUTHORIZATION_DATA, authorizationData);
    }
}
