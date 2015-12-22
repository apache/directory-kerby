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
import org.apache.kerby.kerberos.kerb.type.KrbSequenceType;
import org.apache.kerby.x509.type.SubjectPublicKeyInfo;

import static org.apache.kerby.kerberos.kerb.type.pa.pkinit.AuthPack.MyEnum.*;

/**
 AuthPack ::= SEQUENCE {
     pkAuthenticator         [0] PKAuthenticator,
     clientPublicValue       [1] SubjectPublicKeyInfo OPTIONAL,
     supportedCMSTypes       [2] SEQUENCE OF AlgorithmIdentifier OPTIONAL,
     clientDHNonce           [3] DHNonce OPTIONAL
 }
 */
public class AuthPack extends KrbSequenceType {
    protected enum MyEnum implements EnumType {
        PK_AUTHENTICATOR,
        CLIENT_PUBLIC_VALUE,
        SUPPORTED_CMS_TYPES,
        CLIENT_DH_NONCE,
        SUPPORTED_KDFS;

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
            new ExplicitField(PK_AUTHENTICATOR, PkAuthenticator.class),
            new ExplicitField(CLIENT_PUBLIC_VALUE, SubjectPublicKeyInfo.class),
            new ExplicitField(SUPPORTED_CMS_TYPES, AlgorithmIdentifiers.class),
            new ExplicitField(CLIENT_DH_NONCE, DHNonce.class),
            new ExplicitField(SUPPORTED_KDFS, SupportedKDFs.class)
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
        return getFieldAs(SUPPORTED_CMS_TYPES, AlgorithmIdentifiers.class);
    }

    public void setsupportedCmsTypes(AlgorithmIdentifiers supportedCMSTypes) {
        setFieldAs(SUPPORTED_CMS_TYPES, supportedCMSTypes);
    }

    public DHNonce getClientDhNonce() {
        return getFieldAs(CLIENT_DH_NONCE, DHNonce.class);
    }

    public void setClientDhNonce(DHNonce dhNonce) {
        setFieldAs(CLIENT_DH_NONCE, dhNonce);
    }

    public SupportedKDFs getsupportedKDFs() {
        return getFieldAs(SUPPORTED_KDFS, SupportedKDFs.class);
    }

    public void setsupportedKDFs(SupportedKDFs supportedKDFs) {
        setFieldAs(SUPPORTED_KDFS, supportedKDFs);
    }
}
