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
import org.apache.kerby.x500.type.Name;

import static org.apache.kerby.x509.type.TBSCertificate.MyEnum.*;


/**
 * <pre>
 * TBSCertificate ::= SEQUENCE {
 *      version          [ 0 ]  Version DEFAULT v1(0),
 *      serialNumber            CertificateSerialNumber,
 *      signature               AlgorithmIdentifier,
 *      issuer                  Name,
 *      validity                Validity,
 *      subject                 Name,
 *      subjectPublicKeyInfo    SubjectPublicKeyInfo,
 *      issuerUniqueID    [ 1 ] IMPLICIT UniqueIdentifier OPTIONAL,
 *      subjectUniqueID   [ 2 ] IMPLICIT UniqueIdentifier OPTIONAL,
 *      extensions        [ 3 ] Extensions OPTIONAL
 *  }
 * </pre>
 */
public class TBSCertificate extends Asn1SequenceType {
    protected enum MyEnum implements EnumType {
        VERSION,
        SERIAL_NUMBER,
        SIGNATURE,
        ISSUER,
        VALIDITY,
        SUBJECT,
        SUBJECT_PUBLIC_KEY_INFO,
        ISSUER_UNIQUE_ID,
        SUBJECT_UNIQUE_ID,
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
            new ExplicitField(VERSION, 0, Asn1Integer.class),
            new Asn1FieldInfo(SERIAL_NUMBER, CertificateSerialNumber.class),
            new Asn1FieldInfo(SIGNATURE, AlgorithmIdentifier.class),
            new Asn1FieldInfo(ISSUER, Name.class),
            new Asn1FieldInfo(VALIDITY, AttCertValidityPeriod.class),
            new Asn1FieldInfo(SUBJECT, Name.class),
            new Asn1FieldInfo(SUBJECT_PUBLIC_KEY_INFO, SubjectPublicKeyInfo.class),
            new ImplicitField(ISSUER_UNIQUE_ID, 1, Asn1BitString.class),
            new ImplicitField(SUBJECT_UNIQUE_ID, 2, Asn1BitString.class),
            new ExplicitField(EXTENSIONS, 3, Extensions.class)
    };

    public TBSCertificate() {
        super(fieldInfos);
    }

    public int getVersion() {
        return getFieldAsInteger(VERSION);
    }

    public void setVersion(int version) {
        setFieldAsInt(VERSION, version);
    }

    public CertificateSerialNumber getSerialNumber() {
        return getFieldAs(SERIAL_NUMBER, CertificateSerialNumber.class);
    }

    public void setSerialNumber(CertificateSerialNumber certificateSerialNumber) {
        setFieldAs(SERIAL_NUMBER, certificateSerialNumber);
    }

    public AlgorithmIdentifier getSignature() {
        return getFieldAs(SIGNATURE, AlgorithmIdentifier.class);
    }

    public void setSignature(AlgorithmIdentifier signature) {
        setFieldAs(SIGNATURE, signature);
    }

    public Name getIssuer() {
        return getFieldAs(ISSUER, Name.class);
    }

    public void setIssuer(Name attCertIssuer) {
        setFieldAs(ISSUER, attCertIssuer);
    }

    public AttCertValidityPeriod getValidity() {
        return getFieldAs(VALIDITY, AttCertValidityPeriod.class);
    }

    public void setValidity(AttCertValidityPeriod validity) {
        setFieldAs(VALIDITY, validity);
    }

    public Name getSubject() {
        return getFieldAs(SUBJECT, Name.class);
    }

    public void setSubject(Name subject) {
        setFieldAs(SUBJECT, subject);
    }

    public SubjectPublicKeyInfo getSubjectPublicKeyInfo() {
        return getFieldAs(SUBJECT_PUBLIC_KEY_INFO, SubjectPublicKeyInfo.class);
    }

    public void setSubjectPublicKeyInfo(SubjectPublicKeyInfo subjectPublicKeyInfo) {
        setFieldAs(SUBJECT_PUBLIC_KEY_INFO, subjectPublicKeyInfo);
    }

    public byte[] getIssuerUniqueID() {
        return getFieldAs(ISSUER_UNIQUE_ID, Asn1BitString.class).getValue();
    }

    public void setIssuerUniqueId(byte[] issuerUniqueId) {
        setFieldAs(ISSUER_UNIQUE_ID, new Asn1BitString(issuerUniqueId));
    }

    public byte[] getSubjectUniqueId() {
        return getFieldAs(ISSUER_UNIQUE_ID, Asn1BitString.class).getValue();
    }

    public void setSubjectUniqueId(byte[] issuerUniqueId) {
        setFieldAs(SUBJECT_UNIQUE_ID, new Asn1BitString(issuerUniqueId));
    }

    public Extensions getExtensions() {
        return getFieldAs(EXTENSIONS, Extensions.class);
    }

    public void setExtensions(Extensions extensions) {
        setFieldAs(EXTENSIONS, extensions);
    }
}
