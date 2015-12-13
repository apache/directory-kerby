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
package org.apache.kerby.x509.type;

import org.apache.kerby.asn1.Asn1FieldInfo;
import org.apache.kerby.asn1.EnumType;
import org.apache.kerby.asn1.ImplicitField;
import org.apache.kerby.asn1.type.Asn1SequenceType;

import static org.apache.kerby.x509.type.AuthorityKeyIdentifier.MyEnum.AUTHORITY_CERT_ISSUER;
import static org.apache.kerby.x509.type.AuthorityKeyIdentifier.MyEnum.AUTHORITY_CERT_SERIAL_NUMBER;
import static org.apache.kerby.x509.type.AuthorityKeyIdentifier.MyEnum.KEY_IDENTIFIER;

/**
 *
 * <pre>
 * id-ce-authorityKeyIdentifier OBJECT IDENTIFIER ::=  { id-ce 35 }
 *
 *   AuthorityKeyIdentifier ::= SEQUENCE {
 *        keyIdentifier             [0] IMPLICIT KeyIdentifier           OPTIONAL,
 *        authorityCertIssuer       [1] IMPLICIT GeneralNames            OPTIONAL,
 *        authorityCertSerialNumber [2] IMPLICIT CertificateSerialNumber OPTIONAL
 *      }
 *
 *   KeyIdentifier ::= OCTET STRING
 * </pre>
 *
 */
public class AuthorityKeyIdentifier extends Asn1SequenceType {
    protected enum MyEnum implements EnumType {
        KEY_IDENTIFIER,
        AUTHORITY_CERT_ISSUER,
        AUTHORITY_CERT_SERIAL_NUMBER;

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
        new ImplicitField(KEY_IDENTIFIER, KeyIdentifier.class),
        new ImplicitField(AUTHORITY_CERT_ISSUER, GeneralNames.class),
        new ImplicitField(AUTHORITY_CERT_SERIAL_NUMBER, CertificateSerialNumber.class)
    };

    public AuthorityKeyIdentifier() {
        super(fieldInfos);
    }

    public KeyIdentifier getKeyIdentifier() {
        return getFieldAs(KEY_IDENTIFIER, KeyIdentifier.class);
    }

    public void setKeyIdentifier(KeyIdentifier keyIdentifier) {
        setFieldAs(KEY_IDENTIFIER, keyIdentifier);
    }

    public GeneralNames getAuthorityCertIssuer() {
        return getFieldAs(AUTHORITY_CERT_ISSUER, GeneralNames.class);
    }

    public void setAuthorityCertIssuer(GeneralNames authorityCertIssuer) {
        setFieldAs(AUTHORITY_CERT_ISSUER, authorityCertIssuer);
    }
    
    public CertificateSerialNumber getAuthorityCertSerialNumber() {
        return getFieldAs(AUTHORITY_CERT_SERIAL_NUMBER, CertificateSerialNumber.class);
    }

    public void setAuthorityCertSerialNumber(CertificateSerialNumber authorityCertSerialNumber) {
        setFieldAs(AUTHORITY_CERT_SERIAL_NUMBER, authorityCertSerialNumber);
    }
}
