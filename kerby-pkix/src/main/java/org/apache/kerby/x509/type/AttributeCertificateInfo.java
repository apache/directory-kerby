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
import org.apache.kerby.asn1.type.Asn1BitString;
import org.apache.kerby.asn1.type.Asn1Integer;
import org.apache.kerby.asn1.type.Asn1SequenceType;

/**
 *
 * <pre>
 *  AttributeCertificateInfo ::= SEQUENCE {
 *       version              AttCertVersion -- version is v2,
 *       holder               Holder,
 *       issuer               AttCertIssuer,
 *       signature            AlgorithmIdentifier,
 *       serialNumber         CertificateSerialNumber,
 *       attrCertValidityPeriod   AttCertValidityPeriod,
 *       attributes           SEQUENCE OF Attribute,
 *       issuerUniqueID       UniqueIdentifier OPTIONAL,
 *       extensions           Extensions OPTIONAL
 *  }
 *
 *  AttCertVersion ::= INTEGER { v2(1) }
 *
 *  UniqueIdentifier  ::=  BIT STRING
 * </pre>
 */
public class AttributeCertificateInfo extends Asn1SequenceType {
    protected enum ACInfoField implements EnumType {
        VERSION,
        HOLDER,
        ISSUER,
        SIGNATURE,
        SERIAL_NUMBER,
        ATTR_CERT_VALIDITY_PERIOD,
        ATTRIBUTES,
        ISSUER_UNIQUE_ID,
        EXTENSIONS;

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
        new Asn1FieldInfo(ACInfoField.VERSION, Asn1Integer.class),
        new Asn1FieldInfo(ACInfoField.HOLDER, Holder.class),
        new Asn1FieldInfo(ACInfoField.ISSUER, AttCertIssuer.class),
        new Asn1FieldInfo(ACInfoField.SIGNATURE, AlgorithmIdentifier.class),
        new Asn1FieldInfo(ACInfoField.SERIAL_NUMBER, CertificateSerialNumber.class),
        new Asn1FieldInfo(ACInfoField.ATTR_CERT_VALIDITY_PERIOD, AttCertValidityPeriod.class),
        new Asn1FieldInfo(ACInfoField.ATTRIBUTES, Attributes.class),
        new Asn1FieldInfo(ACInfoField.ISSUER_UNIQUE_ID, Asn1BitString.class),
        new Asn1FieldInfo(ACInfoField.EXTENSIONS, Extensions.class)
    };

    public AttributeCertificateInfo() {
        super(fieldInfos);
    }

    public int getVersion() {
        return getFieldAsInteger(ACInfoField.VERSION);
    }

    public void setVersion(int version) {
        setFieldAsInt(ACInfoField.VERSION, version);
    }

    public Holder getHolder() {
        return getFieldAs(ACInfoField.HOLDER, Holder.class);
    }

    public void setHolder(Holder holder) {
        setFieldAs(ACInfoField.HOLDER, holder);
    }

    public AttCertIssuer getIssuer() {
        return getFieldAs(ACInfoField.ISSUER, AttCertIssuer.class);
    }

    public void setIssuer(AttCertIssuer attCertIssuer) {
        setFieldAs(ACInfoField.ISSUER, attCertIssuer);
    }

    public AlgorithmIdentifier getSignature() {
        return getFieldAs(ACInfoField.SIGNATURE, AlgorithmIdentifier.class);
    }

    public void setSignature(AlgorithmIdentifier signature) {
        setFieldAs(ACInfoField.SIGNATURE, signature);
    }

    public CertificateSerialNumber getSerialNumber() {
        return getFieldAs(ACInfoField.SERIAL_NUMBER, CertificateSerialNumber.class);
    }

    public void setSerialNumber(CertificateSerialNumber certificateSerialNumber) {
        setFieldAs(ACInfoField.SERIAL_NUMBER, certificateSerialNumber);
    }

    public AttCertValidityPeriod getAttrCertValidityPeriod() {
        return getFieldAs(ACInfoField.ATTR_CERT_VALIDITY_PERIOD, AttCertValidityPeriod.class);
    }

    public void setAttrCertValidityPeriod(AttCertValidityPeriod attrCertValidityPeriod) {
        setFieldAs(ACInfoField.ATTR_CERT_VALIDITY_PERIOD, attrCertValidityPeriod);
    }

    public Attributes getAttributes() {
        return getFieldAs(ACInfoField.ATTRIBUTES, Attributes.class);
    }

    public void setAttributes(Attributes attributes) {
        setFieldAs(ACInfoField.ATTRIBUTES, attributes);
    }

    public byte[] getIssuerUniqueID() {
        return getFieldAs(ACInfoField.ISSUER_UNIQUE_ID, Asn1BitString.class).getValue();
    }

    public void setIssuerUniqueId(byte[] issuerUniqueId) {
        setFieldAs(ACInfoField.ISSUER_UNIQUE_ID, new Asn1BitString(issuerUniqueId));
    }

    public Extensions getExtensions() {
        return getFieldAs(ACInfoField.EXTENSIONS, Extensions.class);
    }

    public void setExtensions(Extensions extensions) {
        setFieldAs(ACInfoField.EXTENSIONS, extensions);
    }
}
