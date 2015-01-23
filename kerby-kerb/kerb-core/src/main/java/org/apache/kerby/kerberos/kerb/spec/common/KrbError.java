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
package org.apache.kerby.kerberos.kerb.spec.common;

import org.apache.kerby.asn1.type.Asn1FieldInfo;
import org.apache.kerby.asn1.type.Asn1Integer;
import org.apache.kerby.asn1.type.Asn1OctetString;
import org.apache.kerby.kerberos.kerb.KrbErrorCode;
import org.apache.kerby.kerberos.kerb.spec.KerberosString;
import org.apache.kerby.kerberos.kerb.spec.KerberosTime;

/**
 KRB-ERROR       ::= [APPLICATION 30] SEQUENCE {
 pvno            [0] INTEGER (5),
 msg-type        [1] INTEGER (30),
 ctime           [2] KerberosTime OPTIONAL,
 cusec           [3] Microseconds OPTIONAL,
 stime           [4] KerberosTime,
 susec           [5] Microseconds,
 error-code      [6] Int32,
 crealm          [7] Realm OPTIONAL,
 cname           [8] PrincipalName OPTIONAL,
 realm           [9] Realm -- service realm --,
 sname           [10] PrincipalName -- service name --,
 e-text          [11] KerberosString OPTIONAL,
 e-data          [12] OCTET STRING OPTIONAL
 }
 */
public class KrbError extends KrbMessage {
    private static int CTIME = 2;
    private static int CUSEC = 3;
    private static int STIME = 4;
    private static int SUSEC = 5;
    private static int ERROR_CODE = 6;
    private static int CREALM = 7;
    private static int CNAME = 8;
    private static int REALM = 9;
    private static int SNAME = 10;
    private static int ETEXT = 11;
    private static int EDATA = 12;

    static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[] {
            new Asn1FieldInfo(PVNO, Asn1Integer.class),
            new Asn1FieldInfo(MSG_TYPE, Asn1Integer.class),
            new Asn1FieldInfo(CTIME, KerberosTime.class),
            new Asn1FieldInfo(CUSEC, Asn1Integer.class),
            new Asn1FieldInfo(STIME, KerberosTime.class),
            new Asn1FieldInfo(SUSEC, Asn1Integer.class),
            new Asn1FieldInfo(ERROR_CODE, Asn1Integer.class),
            new Asn1FieldInfo(CREALM, KerberosString.class),
            new Asn1FieldInfo(CNAME, PrincipalName.class),
            new Asn1FieldInfo(REALM, KerberosString.class),
            new Asn1FieldInfo(SNAME, PrincipalName.class),
            new Asn1FieldInfo(ETEXT, KerberosString.class),
            new Asn1FieldInfo(EDATA, Asn1OctetString.class)
    };

    public KrbError() {
        super(KrbMessageType.KRB_ERROR, fieldInfos);
    }

    public KerberosTime getCtime() {
        return getFieldAs(CTIME, KerberosTime.class);
    }

    public void setCtime(KerberosTime ctime) {
        setFieldAs(CTIME, ctime);
    }

    public int getCusec() {
        return getFieldAsInt(CUSEC);
    }

    public void setCusec(int cusec) {
        setFieldAsInt(0, cusec);
    }

    public KerberosTime getStime() {
        return getFieldAs(STIME, KerberosTime.class);
    }

    public void setStime(KerberosTime stime) {
        setFieldAs(STIME, stime);
    }

    public int getSusec() {
        return getFieldAsInt(SUSEC);
    }

    public void setSusec(int susec) {
        setFieldAsInt(0, susec);
    }

    public KrbErrorCode getErrorCode() {
        return KrbErrorCode.fromValue(getFieldAsInt(ERROR_CODE));
    }

    public void setErrorCode(KrbErrorCode errorCode) {
        setField(0, errorCode);
    }

    public String getCrealm() {
        return getFieldAsString(CREALM);
    }

    public void setCrealm(String realm) {
        setFieldAs(CREALM, new KerberosString(realm));
    }

    public PrincipalName getCname() {
        return getFieldAs(CNAME, PrincipalName.class);
    }

    public void setCname(PrincipalName sname) {
        setFieldAs(CNAME, sname);
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

    public String getEtext() {
        return getFieldAsString(ETEXT);
    }

    public void setEtext(String realm) {
        setFieldAs(ETEXT, new KerberosString(realm));
    }

    public byte[] getEdata() {
        return getFieldAsOctetBytes(EDATA);
    }

    public void setEdata(byte[] edata) {
        setFieldAsOctetBytes(EDATA, edata);
    }
}
