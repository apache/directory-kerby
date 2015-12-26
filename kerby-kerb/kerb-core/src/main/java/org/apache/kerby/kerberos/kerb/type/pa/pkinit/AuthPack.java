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

/**
 AuthPack ::= SEQUENCE {
     pkAuthenticator         [0] PKAuthenticator,
     clientPublicValue       [1] SubjectPublicKeyInfo OPTIONAL,
     supportedCMSTypes       [2] SEQUENCE OF AlgorithmIdentifier OPTIONAL,
     clientDHNonce           [3] DHNonce OPTIONAL
     supportedKDFs           [4] SEQUENCE OF KDFAlgorithmId OPTIONAL,
                             -- Contains an unordered set of KDFs supported by the client.
 KDFAlgorithmId ::= SEQUENCE {
     kdf-id            [0] OBJECT IDENTIFIER,
                       -- The object identifier of the KDF
 }
 */
public class AuthPack extends KrbSequenceType {
    protected enum AuthPackField implements EnumType {
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
            new ExplicitField(AuthPackField.PK_AUTHENTICATOR, PkAuthenticator.class),
            new ExplicitField(AuthPackField.CLIENT_PUBLIC_VALUE, SubjectPublicKeyInfo.class),
            new ExplicitField(AuthPackField.SUPPORTED_CMS_TYPES, AlgorithmIdentifiers.class),
            new ExplicitField(AuthPackField.CLIENT_DH_NONCE, DhNonce.class),
            new ExplicitField(AuthPackField.SUPPORTED_KDFS, SupportedKdfs.class)
    };

    public AuthPack() {
        super(fieldInfos);
    }

    public PkAuthenticator getPkAuthenticator() {
        return getFieldAs(AuthPackField.PK_AUTHENTICATOR, PkAuthenticator.class);
    }

    public void setPkAuthenticator(PkAuthenticator pkAuthenticator) {
        setFieldAs(AuthPackField.PK_AUTHENTICATOR, pkAuthenticator);
    }

    public SubjectPublicKeyInfo getClientPublicValue() {
        return getFieldAs(AuthPackField.CLIENT_PUBLIC_VALUE, SubjectPublicKeyInfo.class);
    }

    public void setClientPublicValue(SubjectPublicKeyInfo clientPublicValue) {
        setFieldAs(AuthPackField.CLIENT_PUBLIC_VALUE, clientPublicValue);
    }

    public AlgorithmIdentifiers getsupportedCmsTypes() {
        return getFieldAs(AuthPackField.SUPPORTED_CMS_TYPES, AlgorithmIdentifiers.class);
    }

    public void setsupportedCmsTypes(AlgorithmIdentifiers supportedCMSTypes) {
        setFieldAs(AuthPackField.SUPPORTED_CMS_TYPES, supportedCMSTypes);
    }

    public DhNonce getClientDhNonce() {
        return getFieldAs(AuthPackField.CLIENT_DH_NONCE, DhNonce.class);
    }

    public void setClientDhNonce(DhNonce dhNonce) {
        setFieldAs(AuthPackField.CLIENT_DH_NONCE, dhNonce);
    }

    public SupportedKdfs getsupportedKDFs() {
        return getFieldAs(AuthPackField.SUPPORTED_KDFS, SupportedKdfs.class);
    }

    public void setsupportedKDFs(SupportedKdfs supportedKdfs) {
        setFieldAs(AuthPackField.SUPPORTED_KDFS, supportedKdfs);
    }
}
