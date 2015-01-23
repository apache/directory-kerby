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
package org.apache.kerby.kerberos.kerb.spec.pa.pkinit;

import org.apache.kerby.asn1.type.Asn1FieldInfo;
import org.apache.kerby.asn1.type.Asn1OctetString;
import org.apache.kerby.kerberos.kerb.spec.KrbSequenceType;

/**
 PA-PK-AS-REQ ::= SEQUENCE {
     signedAuthPack          [0] IMPLICIT OCTET STRING,
     trustedCertifiers       [1] SEQUENCE OF ExternalPrincipalIdentifier OPTIONAL,
     kdcPkId                 [2] IMPLICIT OCTET STRING OPTIONAL
 }
 */
public class PaPkAsReq extends KrbSequenceType {
    private static int SIGNED_AUTH_PACK = 0;
    private static int TRUSTED_CERTIFIERS = 1;
    private static int KDC_PKID = 2;

    static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[] {
            new Asn1FieldInfo(SIGNED_AUTH_PACK, Asn1OctetString.class, true),
            new Asn1FieldInfo(TRUSTED_CERTIFIERS, TrustedCertifiers.class),
            new Asn1FieldInfo(KDC_PKID, Asn1OctetString.class, true)
    };

    public PaPkAsReq() {
        super(fieldInfos);
    }

    public byte[] getSignedAuthPack() {
        return getFieldAsOctets(SIGNED_AUTH_PACK);
    }

    public void setSignedAuthPack(byte[] signedAuthPack) {
        setFieldAsOctets(SIGNED_AUTH_PACK, signedAuthPack);
    }

    public TrustedCertifiers getTrustedCertifiers() {
        return getFieldAs(TRUSTED_CERTIFIERS, TrustedCertifiers.class);
    }

    public void setTrustedCertifiers(TrustedCertifiers trustedCertifiers) {
        setFieldAs(TRUSTED_CERTIFIERS, trustedCertifiers);
    }

    public byte[] getKdcPkId() {
        return getFieldAsOctets(KDC_PKID);
    }

    public void setKdcPkId(byte[] kdcPkId) {
        setFieldAsOctets(KDC_PKID, kdcPkId);
    }
}
