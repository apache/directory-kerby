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
import org.apache.kerby.kerberos.kerb.type.KerberosString;
import org.apache.kerby.kerberos.kerb.type.KerberosTime;
import org.apache.kerby.kerberos.kerb.type.KrbAppSequenceType;
import org.apache.kerby.kerberos.kerb.type.ad.AuthorizationData;
import org.apache.kerby.kerberos.kerb.type.base.CheckSum;
import org.apache.kerby.kerberos.kerb.type.base.EncryptionKey;
import org.apache.kerby.kerberos.kerb.type.base.PrincipalName;

/**
 Authenticator   ::= [APPLICATION 2] SEQUENCE  {
 authenticator-vno       [0] INTEGER (5),
 crealm                  [1] Realm,
 cname                   [2] PrincipalName,
 cksum                   [3] Checksum OPTIONAL,
 cusec                   [4] Microseconds,
 ctime                   [5] KerberosTime,
 subkey                  [6] EncryptionKey OPTIONAL,
 seq-number              [7] UInt32 OPTIONAL,
 authorization-data      [8] AuthorizationData OPTIONAL
 }
 */
public class Authenticator extends KrbAppSequenceType {
    public static final int TAG = 2;

    protected enum AuthenticatorField implements EnumType {
        AUTHENTICATOR_VNO,
        CREALM,
        CNAME,
        CKSUM,
        CUSEC,
        CTIME,
        SUBKEY,
        SEQ_NUMBER,
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
            new ExplicitField(AuthenticatorField.AUTHENTICATOR_VNO, Asn1Integer.class),
            new ExplicitField(AuthenticatorField.CREALM, KerberosString.class),
            new ExplicitField(AuthenticatorField.CNAME, PrincipalName.class),
            new ExplicitField(AuthenticatorField.CKSUM, CheckSum.class),
            new ExplicitField(AuthenticatorField.CUSEC, Asn1Integer.class),
            new ExplicitField(AuthenticatorField.CTIME, KerberosTime.class),
            new ExplicitField(AuthenticatorField.SUBKEY, EncryptionKey.class),
            new ExplicitField(AuthenticatorField.SEQ_NUMBER, Asn1Integer.class),
            new ExplicitField(AuthenticatorField.AUTHORIZATION_DATA, AuthorizationData.class)
    };

    public Authenticator() {
        super(TAG, fieldInfos);
    }

    public int getAuthenticatorVno() {
        return getFieldAsInt(AuthenticatorField.AUTHENTICATOR_VNO);
    }

    public void setAuthenticatorVno(int authenticatorVno) {
        setFieldAsInt(AuthenticatorField.AUTHENTICATOR_VNO, authenticatorVno);
    }

    public String getCrealm() {
        return getFieldAsString(AuthenticatorField.CREALM);
    }

    public void setCrealm(String crealm) {
        setFieldAsString(AuthenticatorField.CREALM, crealm);
    }

    public PrincipalName getCname() {
        return getFieldAs(AuthenticatorField.CNAME, PrincipalName.class);
    }

    public void setCname(PrincipalName cname) {
        setFieldAs(AuthenticatorField.CNAME, cname);
    }

    public CheckSum getCksum() {
        return getFieldAs(AuthenticatorField.CKSUM, CheckSum.class);
    }

    public void setCksum(CheckSum cksum) {
        setFieldAs(AuthenticatorField.CKSUM, cksum);
    }

    public int getCusec() {
        return getFieldAsInt(AuthenticatorField.CUSEC);
    }

    public void setCusec(int cusec) {
        setFieldAsInt(AuthenticatorField.CUSEC, cusec);
    }

    public KerberosTime getCtime() {
        return getFieldAsTime(AuthenticatorField.CTIME);
    }

    public void setCtime(KerberosTime ctime) {
        setFieldAs(AuthenticatorField.CTIME, ctime);
    }

    public EncryptionKey getSubKey() {
        return getFieldAs(AuthenticatorField.SUBKEY, EncryptionKey.class);
    }

    public void setSubKey(EncryptionKey subKey) {
        setFieldAs(AuthenticatorField.SUBKEY, subKey);
    }

    public int getSeqNumber() {
        return getFieldAsInt(AuthenticatorField.SEQ_NUMBER);
    }

    public void setSeqNumber(Integer seqNumber) {
        setFieldAsInt(AuthenticatorField.SEQ_NUMBER, seqNumber);
    }

    public AuthorizationData getAuthorizationData() {
        return getFieldAs(AuthenticatorField.AUTHORIZATION_DATA, AuthorizationData.class);
    }

    public void setAuthorizationData(AuthorizationData authorizationData) {
        setFieldAs(AuthenticatorField.AUTHORIZATION_DATA, authorizationData);
    }
}
