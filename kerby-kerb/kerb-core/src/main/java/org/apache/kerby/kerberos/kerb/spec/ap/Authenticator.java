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
package org.apache.kerby.kerberos.kerb.spec.ap;

import org.apache.kerby.asn1.type.Asn1FieldInfo;
import org.apache.kerby.asn1.type.Asn1Integer;
import org.apache.kerby.kerberos.kerb.spec.KerberosString;
import org.apache.kerby.kerberos.kerb.spec.KerberosTime;
import org.apache.kerby.kerberos.kerb.spec.KrbAppSequenceType;
import org.apache.kerby.kerberos.kerb.spec.common.AuthorizationData;
import org.apache.kerby.kerberos.kerb.spec.common.CheckSum;
import org.apache.kerby.kerberos.kerb.spec.common.EncryptionKey;
import org.apache.kerby.kerberos.kerb.spec.common.PrincipalName;

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
    public static int TAG = 2;
    private static int AUTHENTICATOR_VNO = 0;
    private static int CREALM = 1;
    private static int CNAME = 2;
    private static int CKSUM = 3;
    private static int CUSEC = 4;
    private static int CTIME = 5;
    private static int SUBKEY = 6;
    private static int SEQ_NUMBER = 7;
    private static int AUTHORIZATION_DATA = 8;

    static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[] {
            new Asn1FieldInfo(AUTHENTICATOR_VNO, 0, Asn1Integer.class),
            new Asn1FieldInfo(CREALM, 1, KerberosString.class),
            new Asn1FieldInfo(CNAME, 2, PrincipalName.class),
            new Asn1FieldInfo(CKSUM, 3, CheckSum.class),
            new Asn1FieldInfo(CUSEC, 4, Asn1Integer.class),
            new Asn1FieldInfo(CTIME, 5, KerberosTime.class),
            new Asn1FieldInfo(SUBKEY, 6, EncryptionKey.class),
            new Asn1FieldInfo(SEQ_NUMBER, 7, Asn1Integer.class),
            new Asn1FieldInfo(AUTHORIZATION_DATA, 8, AuthorizationData.class)
    };

    public Authenticator() {
        super(TAG, fieldInfos);
    }

    public int getAuthenticatorVno() {
        return getFieldAsInt(AUTHENTICATOR_VNO);
    }

    public void setAuthenticatorVno(int authenticatorVno) {
        setFieldAsInt(AUTHENTICATOR_VNO, authenticatorVno);
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

    public CheckSum getCksum() {
        return getFieldAs(CKSUM, CheckSum.class);
    }

    public void setCksum(CheckSum cksum) {
        setFieldAs(CKSUM, cksum);
    }

    public int getCusec() {
        return getFieldAsInt(CUSEC);
    }

    public void setCusec(int cusec) {
        setFieldAsInt(CUSEC, cusec);
    }

    public KerberosTime getCtime() {
        return getFieldAsTime(CTIME);
    }

    public void setCtime(KerberosTime ctime) {
        setFieldAs(CTIME, ctime);
    }

    public EncryptionKey getSubKey() {
        return getFieldAs(SUBKEY, EncryptionKey.class);
    }

    public void setSubKey(EncryptionKey subKey) {
        setFieldAs(SUBKEY, subKey);
    }

    public int getSeqNumber() {
        return getFieldAsInt(SEQ_NUMBER);
    }

    public void setSeqNumber(Integer seqNumber) {
        setFieldAsInt(SEQ_NUMBER, seqNumber);
    }

    public AuthorizationData getAuthorizationData() {
        return getFieldAs(AUTHORIZATION_DATA, AuthorizationData.class);
    }

    public void setAuthorizationData(AuthorizationData authorizationData) {
        setFieldAs(AUTHORIZATION_DATA, authorizationData);
    }
}
