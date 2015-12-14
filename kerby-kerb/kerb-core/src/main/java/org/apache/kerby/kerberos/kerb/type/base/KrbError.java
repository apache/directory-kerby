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
package org.apache.kerby.kerberos.kerb.type.base;

import org.apache.kerby.asn1.*;
import org.apache.kerby.asn1.type.*;
import org.apache.kerby.kerberos.kerb.KrbErrorCode;
import org.apache.kerby.kerberos.kerb.type.*;

import static org.apache.kerby.kerberos.kerb.type.base.KrbError.MyEnum.*;

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
    protected enum MyEnum implements EnumType {
        PVNO,
        MSG_TYPE,
        CTIME,
        CUSEC,
        STIME,
        SUSEC,
        ERROR_CODE,
        CREALM,
        CNAME,
        REALM,
        SNAME,
        ETEXT,
        EDATA;

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
            new ExplicitField(PVNO, Asn1Integer.class),
            new ExplicitField(MSG_TYPE, Asn1Integer.class),
            new ExplicitField(CTIME, KerberosTime.class),
            new ExplicitField(CUSEC, Asn1Integer.class),
            new ExplicitField(STIME, KerberosTime.class),
            new ExplicitField(SUSEC, Asn1Integer.class),
            new ExplicitField(ERROR_CODE, Asn1Integer.class),
            new ExplicitField(CREALM, KerberosString.class),
            new ExplicitField(CNAME, PrincipalName.class),
            new ExplicitField(REALM, KerberosString.class),
            new ExplicitField(SNAME, PrincipalName.class),
            new ExplicitField(ETEXT, KerberosString.class),
            new ExplicitField(EDATA, Asn1OctetString.class)
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
        setFieldAsInt(CUSEC, cusec);
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
        setFieldAsInt(SUSEC, susec);
    }

    public KrbErrorCode getErrorCode() {
        return KrbErrorCode.fromValue(getFieldAsInt(ERROR_CODE));
    }

    public void setErrorCode(KrbErrorCode errorCode) {
        setField(ERROR_CODE, errorCode);
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
