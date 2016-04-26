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

import org.apache.kerby.asn1.Asn1FieldInfo;
import org.apache.kerby.asn1.EnumType;
import org.apache.kerby.asn1.ExplicitField;
import org.apache.kerby.asn1.type.Asn1Integer;
import org.apache.kerby.asn1.type.Asn1OctetString;
import org.apache.kerby.kerberos.kerb.KrbErrorCode;
import org.apache.kerby.kerberos.kerb.type.KerberosString;
import org.apache.kerby.kerberos.kerb.type.KerberosTime;

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
    protected enum KrbErrorField implements EnumType {
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
            new ExplicitField(KrbErrorField.PVNO, Asn1Integer.class),
            new ExplicitField(KrbErrorField.MSG_TYPE, Asn1Integer.class),
            new ExplicitField(KrbErrorField.CTIME, KerberosTime.class),
            new ExplicitField(KrbErrorField.CUSEC, Asn1Integer.class),
            new ExplicitField(KrbErrorField.STIME, KerberosTime.class),
            new ExplicitField(KrbErrorField.SUSEC, Asn1Integer.class),
            new ExplicitField(KrbErrorField.ERROR_CODE, Asn1Integer.class),
            new ExplicitField(KrbErrorField.CREALM, Realm.class),
            new ExplicitField(KrbErrorField.CNAME, PrincipalName.class),
            new ExplicitField(KrbErrorField.REALM, Realm.class),
            new ExplicitField(KrbErrorField.SNAME, PrincipalName.class),
            new ExplicitField(KrbErrorField.ETEXT, KerberosString.class),
            new ExplicitField(KrbErrorField.EDATA, Asn1OctetString.class)
    };

    public KrbError() {
        super(KrbMessageType.KRB_ERROR, fieldInfos);
    }

    public KerberosTime getCtime() {
        return getFieldAs(KrbErrorField.CTIME, KerberosTime.class);
    }

    public void setCtime(KerberosTime ctime) {
        setFieldAs(KrbErrorField.CTIME, ctime);
    }

    public int getCusec() {
        return getFieldAsInt(KrbErrorField.CUSEC);
    }

    public void setCusec(int cusec) {
        setFieldAsInt(KrbErrorField.CUSEC, cusec);
    }

    public KerberosTime getStime() {
        return getFieldAs(KrbErrorField.STIME, KerberosTime.class);
    }

    public void setStime(KerberosTime stime) {
        setFieldAs(KrbErrorField.STIME, stime);
    }

    public int getSusec() {
        return getFieldAsInt(KrbErrorField.SUSEC);
    }

    public void setSusec(int susec) {
        setFieldAsInt(KrbErrorField.SUSEC, susec);
    }

    public KrbErrorCode getErrorCode() {
        return KrbErrorCode.fromValue(getFieldAsInt(KrbErrorField.ERROR_CODE));
    }

    public void setErrorCode(KrbErrorCode errorCode) {
        setFieldAsInt(KrbErrorField.ERROR_CODE, errorCode.getValue());
    }

    public String getCrealm() {
        return getFieldAsString(KrbErrorField.CREALM);
    }

    public void setCrealm(String realm) {
        setFieldAs(KrbErrorField.CREALM, new Realm(realm));
    }

    public PrincipalName getCname() {
        return getFieldAs(KrbErrorField.CNAME, PrincipalName.class);
    }

    public void setCname(PrincipalName cname) {
        setFieldAs(KrbErrorField.CNAME, cname);
    }

    public PrincipalName getSname() {
        return getFieldAs(KrbErrorField.SNAME, PrincipalName.class);
    }

    public void setSname(PrincipalName sname) {
        setFieldAs(KrbErrorField.SNAME, sname);
    }

    public String getRealm() {
        return getFieldAsString(KrbErrorField.REALM);
    }

    public void setRealm(String realm) {
        setFieldAs(KrbErrorField.REALM, new Realm(realm));
    }

    public String getEtext() {
        return getFieldAsString(KrbErrorField.ETEXT);
    }

    public void setEtext(String text) {
        setFieldAs(KrbErrorField.ETEXT, new KerberosString(text));
    }

    public byte[] getEdata() {
        return getFieldAsOctetBytes(KrbErrorField.EDATA);
    }

    public void setEdata(byte[] edata) {
        setFieldAsOctetBytes(KrbErrorField.EDATA, edata);
    }
}
