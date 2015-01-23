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
import org.apache.kerby.kerberos.kerb.spec.KrbSequenceType;
import org.apache.kerby.kerberos.kerb.spec.x509.SubjectPublicKeyInfo;

/**
 AuthPack ::= SEQUENCE {
     pkAuthenticator         [0] PKAuthenticator,
     clientPublicValue       [1] SubjectPublicKeyInfo OPTIONAL,
     supportedCMSTypes       [2] SEQUENCE OF AlgorithmIdentifier OPTIONAL,
     clientDHNonce           [3] DHNonce OPTIONAL
 }
 */
public class AuthPack extends KrbSequenceType {
    private static int PK_AUTHENTICATOR = 0;
    private static int CLIENT_PUBLIC_VALUE = 1;
    private static int SUPPORTED_CMS_TYPES = 2;
    private static int CLIENT_DH_NONCE = 3;

    static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[] {
            new Asn1FieldInfo(PK_AUTHENTICATOR, PkAuthenticator.class),
            new Asn1FieldInfo(CLIENT_PUBLIC_VALUE, SubjectPublicKeyInfo.class),
            new Asn1FieldInfo(SUPPORTED_CMS_TYPES, AlgorithmIdentifiers.class),
            new Asn1FieldInfo(CLIENT_DH_NONCE, DHNonce.class)
    };

    public AuthPack() {
        super(fieldInfos);
    }

    public PkAuthenticator getPkAuthenticator() {
        return getFieldAs(PK_AUTHENTICATOR, PkAuthenticator.class);
    }

    public void setPkAuthenticator(PkAuthenticator pkAuthenticator) {
        setFieldAs(PK_AUTHENTICATOR, pkAuthenticator);
    }

    public SubjectPublicKeyInfo getClientPublicValue() {
        return getFieldAs(CLIENT_PUBLIC_VALUE, SubjectPublicKeyInfo.class);
    }

    public void setClientPublicValue(SubjectPublicKeyInfo clientPublicValue) {
        setFieldAs(CLIENT_PUBLIC_VALUE, clientPublicValue);
    }

    public AlgorithmIdentifiers getsupportedCmsTypes() {
        return getFieldAs(CLIENT_DH_NONCE, AlgorithmIdentifiers.class);
    }

    public void setsupportedCmsTypes(AlgorithmIdentifiers supportedCMSTypes) {
        setFieldAs(CLIENT_DH_NONCE, supportedCMSTypes);
    }

    public DHNonce getClientDhNonce() {
        return getFieldAs(CLIENT_DH_NONCE, DHNonce.class);
    }

    public void setClientDhNonce(DHNonce dhNonce) {
        setFieldAs(CLIENT_DH_NONCE, dhNonce);
    }
}
