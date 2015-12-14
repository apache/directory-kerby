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

import org.apache.kerby.asn1.*;
import org.apache.kerby.asn1.type.Asn1Integer;
import org.apache.kerby.kerberos.kerb.type.*;
import org.apache.kerby.kerberos.kerb.type.ad.AuthorizationData;
import org.apache.kerby.kerberos.kerb.type.base.*;
import org.apache.kerby.kerberos.kerb.type.ticket.Tickets;

import java.util.*;

import static org.apache.kerby.kerberos.kerb.type.kdc.KdcReqBody.MyEnum.*;

/**
 KDC-REQ-BODY    ::= SEQUENCE {
 kdc-options             [0] KDCOptions,
 cname                   [1] PrincipalName OPTIONAL
 -- Used only in AS-REQ --,
 realm                   [2] Realm
 -- Server's realm
 -- Also client's in AS-REQ --,
 sname                   [3] PrincipalName OPTIONAL,
 from                    [4] KerberosTime OPTIONAL,
 till                    [5] KerberosTime,
 rtime                   [6] KerberosTime OPTIONAL,
 nonce                   [7] UInt32,
 etype                   [8] SEQUENCE OF Int32 -- EncryptionType
 -- in preference order --,
 addresses               [9] HostAddresses OPTIONAL,
 enc-authorization-data  [10] EncryptedData OPTIONAL
 -- AuthorizationData --,
 additional-tickets      [11] SEQUENCE OF Ticket OPTIONAL
 -- NOTE: not empty
 }
 */
public class KdcReqBody extends KrbSequenceType {
    protected enum MyEnum implements EnumType {
        KDC_OPTIONS,
        CNAME,
        REALM,
        SNAME,
        FROM,
        TILL,
        RTIME,
        NONCE,
        ETYPE,
        ADDRESSES,
        ENC_AUTHORIZATION_DATA,
        ADDITIONAL_TICKETS;

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
            new ExplicitField(KDC_OPTIONS, KdcOptions.class),
            new ExplicitField(CNAME, PrincipalName.class),
            new ExplicitField(REALM, KerberosString.class),
            new ExplicitField(SNAME, PrincipalName.class),
            new ExplicitField(FROM, KerberosTime.class),
            new ExplicitField(TILL, KerberosTime.class),
            new ExplicitField(RTIME, KerberosTime.class),
            new ExplicitField(NONCE, Asn1Integer.class),
            new ExplicitField(ETYPE, KrbIntegers.class),
            new ExplicitField(ADDRESSES, HostAddresses.class),
            new ExplicitField(ENC_AUTHORIZATION_DATA, AuthorizationData.class),
            new ExplicitField(ADDITIONAL_TICKETS, Tickets.class)
    };

    public KdcReqBody() {
        super(fieldInfos);
    }

    private AuthorizationData authorizationData;

    public KerberosTime getFrom() {
        return getFieldAs(FROM, KerberosTime.class);
    }

    public void setFrom(KerberosTime from) {
        setFieldAs(FROM, from);
    }

    public KerberosTime getTill() {
        return getFieldAs(TILL, KerberosTime.class);
    }

    public void setTill(KerberosTime till) {
        setFieldAs(TILL, till);
    }

    public KerberosTime getRtime() {
        return getFieldAs(RTIME, KerberosTime.class);
    }

    public void setRtime(KerberosTime rtime) {
        setFieldAs(RTIME, rtime);
    }

    public int getNonce() {
        return getFieldAsInt(NONCE);
    }

    public void setNonce(int nonce) {
        setFieldAsInt(NONCE, nonce);
    }

    public List<EncryptionType> getEtypes() {
        KrbIntegers values = getFieldAs(ETYPE, KrbIntegers.class);
        if (values == null) {
            return Collections.emptyList();
        }

        List<EncryptionType> results = new ArrayList<EncryptionType>();
        for (Integer value : values.getValues()) {
            results.add(EncryptionType.fromValue(value));
        }
        return results;
    }

    public void setEtypes(List<EncryptionType> etypes) {
        List<Integer> values = new ArrayList<Integer>();
        for (EncryptionType etype: etypes) {
            values.add(etype.getValue());
        }
        KrbIntegers value = new KrbIntegers(values);
        setFieldAs(ETYPE, value);
    }

    public HostAddresses getAddresses() {
        return getFieldAs(ADDRESSES, HostAddresses.class);
    }

    public void setAddresses(HostAddresses addresses) {
        setFieldAs(ADDRESSES, addresses);
    }

    public EncryptedData getEncryptedAuthorizationData() {
        return getFieldAs(ENC_AUTHORIZATION_DATA, EncryptedData.class);
    }

    public void setEncryptedAuthorizationData(EncryptedData encAuthorizationData) {
        setFieldAs(ENC_AUTHORIZATION_DATA, encAuthorizationData);
    }

    public AuthorizationData getAuthorizationData() {
        return authorizationData;
    }

    public void setAuthorizationData(AuthorizationData authorizationData) {
        this.authorizationData = authorizationData;
    }

    public Tickets getAdditionalTickets() {
        return getFieldAs(ADDITIONAL_TICKETS, Tickets.class);
    }

    public void setAdditionalTickets(Tickets additionalTickets) {
        setFieldAs(ADDITIONAL_TICKETS, additionalTickets);
    }

    public KdcOptions getKdcOptions() {
        return getFieldAs(KDC_OPTIONS, KdcOptions.class);
    }

    public void setKdcOptions(KdcOptions kdcOptions) {
        setFieldAs(KDC_OPTIONS, kdcOptions);
    }

    public PrincipalName getSname() {
        return getFieldAs(SNAME, PrincipalName.class);
    }

    public void setSname(PrincipalName sname) {
        setFieldAs(SNAME, sname);
    }

    public PrincipalName getCname() {
        return getFieldAs(CNAME, PrincipalName.class);
    }

    public void setCname(PrincipalName cname) {
        setFieldAs(CNAME, cname);
    }

    public String getRealm() {
        return getFieldAsString(REALM);
    }

    public void setRealm(String realm) {
        setFieldAs(REALM, new KerberosString(realm));
    }
}
