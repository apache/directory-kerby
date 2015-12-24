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
package org.apache.kerby.kerberos.kerb.type.pa.pkinit;

import org.apache.kerby.asn1.Asn1FieldInfo;
import org.apache.kerby.asn1.EnumType;
import org.apache.kerby.asn1.ExplicitField;
import org.apache.kerby.asn1.ImplicitField;
import org.apache.kerby.asn1.type.Asn1OctetString;
import org.apache.kerby.kerberos.kerb.type.KrbSequenceType;

/**
 PA-PK-AS-REQ ::= SEQUENCE {
     signedAuthPack          [0] IMPLICIT OCTET STRING,
     trustedCertifiers       [1] SEQUENCE OF ExternalPrincipalIdentifier OPTIONAL,
     kdcPkId                 [2] IMPLICIT OCTET STRING OPTIONAL
 }
 */
public class PaPkAsReq extends KrbSequenceType {
    protected enum PaPkAsReqField implements EnumType {
        SIGNED_AUTH_PACK,
        TRUSTED_CERTIFIERS,
        KDC_PKID;

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
            new ImplicitField(PaPkAsReqField.SIGNED_AUTH_PACK, Asn1OctetString.class),
            new ExplicitField(PaPkAsReqField.TRUSTED_CERTIFIERS, TrustedCertifiers.class),
            new ImplicitField(PaPkAsReqField.KDC_PKID, Asn1OctetString.class)
    };

    public PaPkAsReq() {
        super(fieldInfos);
    }

    public byte[] getSignedAuthPack() {
        return getFieldAsOctets(PaPkAsReqField.SIGNED_AUTH_PACK);
    }

    public void setSignedAuthPack(byte[] signedAuthPack) {
        setFieldAsOctets(PaPkAsReqField.SIGNED_AUTH_PACK, signedAuthPack);
    }

    public TrustedCertifiers getTrustedCertifiers() {
        return getFieldAs(PaPkAsReqField.TRUSTED_CERTIFIERS, TrustedCertifiers.class);
    }

    public void setTrustedCertifiers(TrustedCertifiers trustedCertifiers) {
        setFieldAs(PaPkAsReqField.TRUSTED_CERTIFIERS, trustedCertifiers);
    }

    public byte[] getKdcPkId() {
        return getFieldAsOctets(PaPkAsReqField.KDC_PKID);
    }

    public void setKdcPkId(byte[] kdcPkId) {
        setFieldAsOctets(PaPkAsReqField.KDC_PKID, kdcPkId);
    }
}
