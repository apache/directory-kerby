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
import org.apache.kerby.kerberos.kerb.type.KerberosTime;
import org.apache.kerby.kerberos.kerb.type.KrbAppSequenceType;
import org.apache.kerby.kerberos.kerb.type.base.EncryptionKey;
import org.apache.kerby.kerberos.kerb.type.base.HostAddresses;
import org.apache.kerby.kerberos.kerb.type.base.LastReq;
import org.apache.kerby.kerberos.kerb.type.base.PrincipalName;
import org.apache.kerby.kerberos.kerb.type.ticket.TicketFlags;

/**
 EncKDCRepPart   ::= SEQUENCE {
 key             [0] EncryptionKey,
 last-req        [1] LastReq,
 nonce           [2] UInt32,
 key-expiration  [3] KerberosTime OPTIONAL,
 flags           [4] TicketFlags,
 authtime        [5] KerberosTime,
 starttime       [6] KerberosTime OPTIONAL,
 endtime         [7] KerberosTime,
 renew-till      [8] KerberosTime OPTIONAL,
 srealm          [9] Realm,
 sname           [10] PrincipalName,
 caddr           [11] HostAddresses OPTIONAL
 }
 */
public abstract class EncKdcRepPart extends KrbAppSequenceType {
    protected enum EncKdcRepPartField implements EnumType {
        KEY,
        LAST_REQ,
        NONCE,
        KEY_EXPIRATION,
        FLAGS,
        AUTHTIME,
        STARTTIME,
        ENDTIME,
        RENEW_TILL,
        SREALM,
        SNAME,
        CADDR;

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
            new ExplicitField(EncKdcRepPartField.KEY, EncryptionKey.class),
            new ExplicitField(EncKdcRepPartField.LAST_REQ, LastReq.class),
            new ExplicitField(EncKdcRepPartField.NONCE, Asn1Integer.class),
            new ExplicitField(EncKdcRepPartField.KEY_EXPIRATION, KerberosTime.class),
            new ExplicitField(EncKdcRepPartField.FLAGS, TicketFlags.class),
            new ExplicitField(EncKdcRepPartField.AUTHTIME, KerberosTime.class),
            new ExplicitField(EncKdcRepPartField.STARTTIME, KerberosTime.class),
            new ExplicitField(EncKdcRepPartField.ENDTIME, KerberosTime.class),
            new ExplicitField(EncKdcRepPartField.RENEW_TILL, KerberosTime.class),
            new ExplicitField(EncKdcRepPartField.SREALM, KerberosString.class),
            new ExplicitField(EncKdcRepPartField.SNAME, PrincipalName.class),
            new ExplicitField(EncKdcRepPartField.CADDR, HostAddresses.class)
    };

    public EncKdcRepPart(int tagNo) {
        super(tagNo, fieldInfos);
    }

    public EncryptionKey getKey() {
        return getFieldAs(EncKdcRepPartField.KEY, EncryptionKey.class);
    }

    public void setKey(EncryptionKey key) {
        setFieldAs(EncKdcRepPartField.KEY, key);
    }

    public LastReq getLastReq() {
        return getFieldAs(EncKdcRepPartField.LAST_REQ, LastReq.class);
    }

    public void setLastReq(LastReq lastReq) {
        setFieldAs(EncKdcRepPartField.LAST_REQ, lastReq);
    }

    public int getNonce() {
        return getFieldAsInt(EncKdcRepPartField.NONCE);
    }

    public void setNonce(int nonce) {
        setFieldAsInt(EncKdcRepPartField.NONCE, nonce);
    }

    public KerberosTime getKeyExpiration() {
        return getFieldAsTime(EncKdcRepPartField.KEY_EXPIRATION);
    }

    public void setKeyExpiration(KerberosTime keyExpiration) {
        setFieldAs(EncKdcRepPartField.KEY_EXPIRATION, keyExpiration);
    }

    public TicketFlags getFlags() {
        return getFieldAs(EncKdcRepPartField.FLAGS, TicketFlags.class);
    }

    public void setFlags(TicketFlags flags) {
        setFieldAs(EncKdcRepPartField.FLAGS, flags);
    }

    public KerberosTime getAuthTime() {
        return getFieldAsTime(EncKdcRepPartField.AUTHTIME);
    }

    public void setAuthTime(KerberosTime authTime) {
        setFieldAs(EncKdcRepPartField.AUTHTIME, authTime);
    }

    public KerberosTime getStartTime() {
        return getFieldAsTime(EncKdcRepPartField.STARTTIME);
    }

    public void setStartTime(KerberosTime startTime) {
        setFieldAs(EncKdcRepPartField.STARTTIME, startTime);
    }

    public KerberosTime getEndTime() {
        return getFieldAsTime(EncKdcRepPartField.ENDTIME);
    }

    public void setEndTime(KerberosTime endTime) {
        setFieldAs(EncKdcRepPartField.ENDTIME, endTime);
    }

    public KerberosTime getRenewTill() {
        return getFieldAsTime(EncKdcRepPartField.RENEW_TILL);
    }

    public void setRenewTill(KerberosTime renewTill) {
        setFieldAs(EncKdcRepPartField.RENEW_TILL, renewTill);
    }

    public String getSrealm() {
        return getFieldAsString(EncKdcRepPartField.SREALM);
    }

    public void setSrealm(String srealm) {
        setFieldAsString(EncKdcRepPartField.SREALM, srealm);
    }

    public PrincipalName getSname() {
        return getFieldAs(EncKdcRepPartField.SNAME, PrincipalName.class);
    }

    public void setSname(PrincipalName sname) {
        setFieldAs(EncKdcRepPartField.SNAME, sname);
    }

    public HostAddresses getCaddr() {
        return getFieldAs(EncKdcRepPartField.CADDR, HostAddresses.class);
    }

    public void setCaddr(HostAddresses caddr) {
        setFieldAs(EncKdcRepPartField.CADDR, caddr);
    }
}
