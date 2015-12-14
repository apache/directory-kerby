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

import org.apache.kerby.asn1.*;
import org.apache.kerby.asn1.type.*;

import static org.apache.kerby.x509.type.IssuerSerial.MyEnum.*;

/**
 * <pre>
 *  IssuerSerial  ::=  SEQUENCE {
 *       issuer         GeneralNames,
 *       serial         CertificateSerialNumber,
 *       issuerUID      UniqueIdentifier OPTIONAL
 *  }
 * </pre>
 */
public class IssuerSerial extends Asn1SequenceType {
    protected enum MyEnum implements EnumType {
        ISSUER,
        SERIAL,
        ISSUER_UID;

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
        new Asn1FieldInfo(ISSUER, GeneralNames.class),
        new Asn1FieldInfo(SERIAL, CertificateSerialNumber.class),
        new Asn1FieldInfo(ISSUER_UID, Asn1BitString.class)
    };

    public IssuerSerial() {
        super(fieldInfos);
    }

    public GeneralNames getIssuer() {
        return getFieldAs(ISSUER, GeneralNames.class);
    }

    public void setIssuer(GeneralNames issuer) {
        setFieldAs(ISSUER, issuer);
    }

    public CertificateSerialNumber getSerial() {
        return getFieldAs(SERIAL, CertificateSerialNumber.class);
    }

    public void setSerial(CertificateSerialNumber serial) {
        setFieldAs(SERIAL, serial);
    }

    public Asn1BitString getIssuerUID() {
        return getFieldAs(ISSUER_UID, Asn1BitString.class);
    }

    public void setIssuerUID(Asn1BitString issuerUID) {
        setFieldAs(ISSUER_UID, issuerUID);
    }
}
