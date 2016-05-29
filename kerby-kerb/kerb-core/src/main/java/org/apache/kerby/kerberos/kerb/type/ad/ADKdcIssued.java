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
package org.apache.kerby.kerberos.kerb.type.ad;

import java.io.IOException;

import org.apache.kerby.asn1.Asn1Dumper;
import org.apache.kerby.asn1.Asn1FieldInfo;
import org.apache.kerby.asn1.EnumType;
import org.apache.kerby.asn1.ExplicitField;
import org.apache.kerby.kerberos.kerb.type.KrbSequenceType;
import org.apache.kerby.kerberos.kerb.type.base.CheckSum;
import org.apache.kerby.kerberos.kerb.type.base.PrincipalName;
import org.apache.kerby.kerberos.kerb.type.base.Realm;

/**
 * <pre>
 *    AD-KDCIssued            ::= SEQUENCE {
 *         ad-checksum     [0] Checksum,
 *         i-realm         [1] Realm OPTIONAL,
 *         i-sname         [2] PrincipalName OPTIONAL,
 *         elements        [3] AuthorizationData
 *    }
 * </pre>
 * 
 * Contributed to the Apache Kerby Project by: Prodentity - Corrales, NM
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache DirectoryProject</a>
 */
public class ADKdcIssued extends AuthorizationDataEntry {

    private KdcIssued myKdcIssued;

    private static class KdcIssued extends KrbSequenceType {

        enum KdcIssuedField implements EnumType {
            AD_CHECKSUM, I_REALM, I_SNAME, ELEMENTS;

            @Override
            public int getValue() {
                return ordinal();
            }

            @Override
            public String getName() {
                return name();
            }
        }

        /** The AuthorizationDataEntry's fields */
        private static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[] {
                new ExplicitField(KdcIssuedField.AD_CHECKSUM, CheckSum.class),
                new ExplicitField(KdcIssuedField.I_REALM, Realm.class),
                new ExplicitField(KdcIssuedField.I_SNAME, PrincipalName.class),
                new ExplicitField(KdcIssuedField.ELEMENTS, AuthorizationData.class)};

        KdcIssued() {
            super(fieldInfos);
        }

        public CheckSum getCheckSum() {
            return getFieldAs(KdcIssuedField.AD_CHECKSUM, CheckSum.class);
        }

        public void setCheckSum(CheckSum chkSum) {
            setFieldAs(KdcIssuedField.AD_CHECKSUM, chkSum);
        }

        public Realm getRealm() {
            return getFieldAs(KdcIssuedField.I_REALM, Realm.class);
        }

        public void setRealm(Realm realm) {
            setFieldAs(KdcIssuedField.I_REALM, realm);
        }

        public PrincipalName getSname() {
            return getFieldAs(KdcIssuedField.I_SNAME, PrincipalName.class);
        }

        public void setSname(PrincipalName sName) {
            setFieldAs(KdcIssuedField.I_SNAME, sName);
        }

        public AuthorizationData getAuthzData() {
            return getFieldAs(KdcIssuedField.ELEMENTS, AuthorizationData.class);
        }

        public void setAuthzData(AuthorizationData authzData) {
            setFieldAs(KdcIssuedField.ELEMENTS, authzData);
        }
    }

    public ADKdcIssued() {
        super(AuthorizationType.AD_KDC_ISSUED);
        myKdcIssued = new KdcIssued();
        myKdcIssued.outerEncodeable = this;
    }

    public ADKdcIssued(byte[] encoded) throws IOException {
        this();
        myKdcIssued.decode(encoded);
    }

    public CheckSum getCheckSum() {
        return myKdcIssued.getCheckSum();
    }

    public void setCheckSum(CheckSum chkSum) {
        myKdcIssued.setCheckSum(chkSum);
    }

    public Realm getRealm() {
        return myKdcIssued.getRealm();
    }

    public void setRealm(Realm realm) {
        myKdcIssued.setRealm(realm);
    }

    public PrincipalName getSname() {
        return myKdcIssued.getSname();
    }

    public void setSname(PrincipalName sName) {
        myKdcIssued.setSname(sName);
    }

    public AuthorizationData getAuthorizationData() {
        return myKdcIssued.getAuthzData();
    }

    public void setAuthzData(AuthorizationData authzData) {
        myKdcIssued.setAuthzData(authzData);
    }

    @Override
    protected int encodingBodyLength() throws IOException {
        if (bodyLength == -1) {
            setAuthzData(myKdcIssued.encode());
            bodyLength = super.encodingBodyLength();
        }
        return bodyLength;
    };

    @Override
    public void dumpWith(Asn1Dumper dumper, int indents) {
        super.dumpWith(dumper, indents);
        dumper.newLine();
        myKdcIssued.dumpWith(dumper, indents + 8);
    }
}
