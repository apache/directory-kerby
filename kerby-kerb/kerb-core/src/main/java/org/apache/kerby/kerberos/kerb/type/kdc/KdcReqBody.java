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

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.apache.kerby.asn1.Asn1FieldInfo;
import org.apache.kerby.asn1.EnumType;
import org.apache.kerby.asn1.ExplicitField;
import org.apache.kerby.asn1.type.Asn1Integer;
import org.apache.kerby.kerberos.kerb.type.KerberosString;
import org.apache.kerby.kerberos.kerb.type.KerberosTime;
import org.apache.kerby.kerberos.kerb.type.KrbIntegers;
import org.apache.kerby.kerberos.kerb.type.KrbSequenceType;
import org.apache.kerby.kerberos.kerb.type.ad.AuthorizationData;
import org.apache.kerby.kerberos.kerb.type.base.EncryptedData;
import org.apache.kerby.kerberos.kerb.type.base.EncryptionType;
import org.apache.kerby.kerberos.kerb.type.base.HostAddresses;
import org.apache.kerby.kerberos.kerb.type.base.PrincipalName;
import org.apache.kerby.kerberos.kerb.type.ticket.Tickets;

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
    protected enum KdcReqBodyField implements EnumType {
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
            new ExplicitField(KdcReqBodyField.KDC_OPTIONS, KdcOptions.class),
            new ExplicitField(KdcReqBodyField.CNAME, PrincipalName.class),
            new ExplicitField(KdcReqBodyField.REALM, KerberosString.class),
            new ExplicitField(KdcReqBodyField.SNAME, PrincipalName.class),
            new ExplicitField(KdcReqBodyField.FROM, KerberosTime.class),
            new ExplicitField(KdcReqBodyField.TILL, KerberosTime.class),
            new ExplicitField(KdcReqBodyField.RTIME, KerberosTime.class),
            new ExplicitField(KdcReqBodyField.NONCE, Asn1Integer.class),
            new ExplicitField(KdcReqBodyField.ETYPE, KrbIntegers.class),
            new ExplicitField(KdcReqBodyField.ADDRESSES, HostAddresses.class),
            new ExplicitField(KdcReqBodyField.ENC_AUTHORIZATION_DATA, AuthorizationData.class),
            new ExplicitField(KdcReqBodyField.ADDITIONAL_TICKETS, Tickets.class)
    };

    public KdcReqBody() {
        super(fieldInfos);
    }

    private AuthorizationData authorizationData;

    public KerberosTime getFrom() {
        return getFieldAs(KdcReqBodyField.FROM, KerberosTime.class);
    }

    public void setFrom(KerberosTime from) {
        setFieldAs(KdcReqBodyField.FROM, from);
    }

    public KerberosTime getTill() {
        return getFieldAs(KdcReqBodyField.TILL, KerberosTime.class);
    }

    public void setTill(KerberosTime till) {
        setFieldAs(KdcReqBodyField.TILL, till);
    }

    public KerberosTime getRtime() {
        return getFieldAs(KdcReqBodyField.RTIME, KerberosTime.class);
    }

    public void setRtime(KerberosTime rtime) {
        setFieldAs(KdcReqBodyField.RTIME, rtime);
    }

    public int getNonce() {
        return getFieldAsInt(KdcReqBodyField.NONCE);
    }

    public void setNonce(int nonce) {
        setFieldAsInt(KdcReqBodyField.NONCE, nonce);
    }

    public List<EncryptionType> getEtypes() {
        KrbIntegers values = getFieldAs(KdcReqBodyField.ETYPE, KrbIntegers.class);
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
        setFieldAs(KdcReqBodyField.ETYPE, value);
    }

    public HostAddresses getAddresses() {
        return getFieldAs(KdcReqBodyField.ADDRESSES, HostAddresses.class);
    }

    public void setAddresses(HostAddresses addresses) {
        setFieldAs(KdcReqBodyField.ADDRESSES, addresses);
    }

    public EncryptedData getEncryptedAuthorizationData() {
        return getFieldAs(KdcReqBodyField.ENC_AUTHORIZATION_DATA, EncryptedData.class);
    }

    public void setEncryptedAuthorizationData(EncryptedData encAuthorizationData) {
        setFieldAs(KdcReqBodyField.ENC_AUTHORIZATION_DATA, encAuthorizationData);
    }

    public AuthorizationData getAuthorizationData() {
        return authorizationData;
    }

    public void setAuthorizationData(AuthorizationData authorizationData) {
        this.authorizationData = authorizationData;
    }

    public Tickets getAdditionalTickets() {
        return getFieldAs(KdcReqBodyField.ADDITIONAL_TICKETS, Tickets.class);
    }

    public void setAdditionalTickets(Tickets additionalTickets) {
        setFieldAs(KdcReqBodyField.ADDITIONAL_TICKETS, additionalTickets);
    }

    public KdcOptions getKdcOptions() {
        return getFieldAs(KdcReqBodyField.KDC_OPTIONS, KdcOptions.class);
    }

    public void setKdcOptions(KdcOptions kdcOptions) {
        setFieldAs(KdcReqBodyField.KDC_OPTIONS, kdcOptions);
    }

    public PrincipalName getSname() {
        return getFieldAs(KdcReqBodyField.SNAME, PrincipalName.class);
    }

    public void setSname(PrincipalName sname) {
        setFieldAs(KdcReqBodyField.SNAME, sname);
    }

    public PrincipalName getCname() {
        return getFieldAs(KdcReqBodyField.CNAME, PrincipalName.class);
    }

    public void setCname(PrincipalName cname) {
        setFieldAs(KdcReqBodyField.CNAME, cname);
    }

    public String getRealm() {
        return getFieldAsString(KdcReqBodyField.REALM);
    }

    public void setRealm(String realm) {
        setFieldAs(KdcReqBodyField.REALM, new KerberosString(realm));
    }
}
