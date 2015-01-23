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
package org.apache.kerby.kerberos.kerb.spec.kdc;

import org.apache.kerby.asn1.type.Asn1FieldInfo;
import org.apache.kerby.asn1.type.Asn1Integer;
import org.apache.kerby.kerberos.kerb.spec.KerberosString;
import org.apache.kerby.kerberos.kerb.spec.KerberosTime;
import org.apache.kerby.kerberos.kerb.spec.KrbAppSequenceType;
import org.apache.kerby.kerberos.kerb.spec.common.EncryptionKey;
import org.apache.kerby.kerberos.kerb.spec.common.HostAddresses;
import org.apache.kerby.kerberos.kerb.spec.common.LastReq;
import org.apache.kerby.kerberos.kerb.spec.common.PrincipalName;
import org.apache.kerby.kerberos.kerb.spec.ticket.TicketFlags;

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
    private static int KEY = 0;
    private static int LAST_REQ = 1;
    private static int NONCE = 2;
    private static int KEY_EXPIRATION = 3;
    private static int FLAGS = 4;
    private static int AUTHTIME = 5;
    private static int STARTTIME = 6;
    private static int ENDTIME = 7;
    private static int RENEW_TILL = 8;
    private static int SREALM = 9;
    private static int SNAME = 10;
    private static int CADDR = 11;

    static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[] {
            new Asn1FieldInfo(KEY, EncryptionKey.class),
            new Asn1FieldInfo(LAST_REQ, LastReq.class),
            new Asn1FieldInfo(NONCE, Asn1Integer.class),
            new Asn1FieldInfo(KEY_EXPIRATION, KerberosTime.class),
            new Asn1FieldInfo(FLAGS, TicketFlags.class),
            new Asn1FieldInfo(AUTHTIME, KerberosTime.class),
            new Asn1FieldInfo(STARTTIME, KerberosTime.class),
            new Asn1FieldInfo(ENDTIME, KerberosTime.class),
            new Asn1FieldInfo(RENEW_TILL, KerberosTime.class),
            new Asn1FieldInfo(SREALM, KerberosString.class),
            new Asn1FieldInfo(SNAME, PrincipalName.class),
            new Asn1FieldInfo(CADDR, HostAddresses.class)
    };

    public EncKdcRepPart(int tagNo) {
        super(tagNo, fieldInfos);
    }

    public EncryptionKey getKey() {
        return getFieldAs(KEY, EncryptionKey.class);
    }

    public void setKey(EncryptionKey key) {
        setFieldAs(KEY, key);
    }

    public LastReq getLastReq() {
        return getFieldAs(LAST_REQ, LastReq.class);
    }

    public void setLastReq(LastReq lastReq) {
        setFieldAs(LAST_REQ, lastReq);
    }

    public int getNonce() {
        return getFieldAsInt(NONCE);
    }

    public void setNonce(int nonce) {
        setFieldAsInt(NONCE, nonce);
    }

    public KerberosTime getKeyExpiration() {
        return getFieldAsTime(KEY_EXPIRATION);
    }

    public void setKeyExpiration(KerberosTime keyExpiration) {
        setFieldAs(KEY_EXPIRATION, keyExpiration);
    }

    public TicketFlags getFlags() {
        return getFieldAs(FLAGS, TicketFlags.class);
    }

    public void setFlags(TicketFlags flags) {
        setFieldAs(FLAGS, flags);
    }

    public KerberosTime getAuthTime() {
        return getFieldAsTime(AUTHTIME);
    }

    public void setAuthTime(KerberosTime authTime) {
        setFieldAs(AUTHTIME, authTime);
    }

    public KerberosTime getStartTime() {
        return getFieldAsTime(STARTTIME);
    }

    public void setStartTime(KerberosTime startTime) {
        setFieldAs(STARTTIME, startTime);
    }

    public KerberosTime getEndTime() {
        return getFieldAsTime(ENDTIME);
    }

    public void setEndTime(KerberosTime endTime) {
        setFieldAs(ENDTIME, endTime);
    }

    public KerberosTime getRenewTill() {
        return getFieldAsTime(RENEW_TILL);
    }

    public void setRenewTill(KerberosTime renewTill) {
        setFieldAs(RENEW_TILL, renewTill);
    }

    public String getSrealm() {
        return getFieldAsString(SREALM);
    }

    public void setSrealm(String srealm) {
        setFieldAsString(SREALM, srealm);
    }

    public PrincipalName getSname() {
        return getFieldAs(SNAME, PrincipalName.class);
    }

    public void setSname(PrincipalName sname) {
        setFieldAs(SNAME, sname);
    }

    public HostAddresses getCaddr() {
        return getFieldAs(CADDR, HostAddresses.class);
    }

    public void setCaddr(HostAddresses caddr) {
        setFieldAs(CADDR, caddr);
    }
}
