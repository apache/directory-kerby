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
import org.apache.kerby.asn1.ExplicitField;
import org.apache.kerby.asn1.ImplicitField;
import org.apache.kerby.asn1.type.Asn1BitString;
import org.apache.kerby.asn1.type.Asn1Integer;
import org.apache.kerby.asn1.type.Asn1SequenceType;
import org.apache.kerby.x500.type.Name;

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
    protected enum TBSCertificateField implements EnumType {
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
            new ExplicitField(TBSCertificateField.VERSION, Asn1Integer.class),
            new Asn1FieldInfo(TBSCertificateField.SERIAL_NUMBER, CertificateSerialNumber.class),
            new Asn1FieldInfo(TBSCertificateField.SIGNATURE, AlgorithmIdentifier.class),
            new Asn1FieldInfo(TBSCertificateField.ISSUER, Name.class),
            new Asn1FieldInfo(TBSCertificateField.VALIDITY, AttCertValidityPeriod.class),
            new Asn1FieldInfo(TBSCertificateField.SUBJECT, Name.class),
            new Asn1FieldInfo(TBSCertificateField.SUBJECT_PUBLIC_KEY_INFO, SubjectPublicKeyInfo.class),
            new ImplicitField(TBSCertificateField.ISSUER_UNIQUE_ID, 1, Asn1BitString.class),
            new ImplicitField(TBSCertificateField.SUBJECT_UNIQUE_ID, 2, Asn1BitString.class),
            new ExplicitField(TBSCertificateField.EXTENSIONS, 3, Extensions.class)
    };

    public TBSCertificate() {
        super(fieldInfos);
    }

    public int getVersion() {
        return getFieldAsInteger(TBSCertificateField.VERSION);
    }

    public void setVersion(int version) {
        setFieldAsInt(TBSCertificateField.VERSION, version);
    }

    public CertificateSerialNumber getSerialNumber() {
        return getFieldAs(TBSCertificateField.SERIAL_NUMBER, CertificateSerialNumber.class);
    }

    public void setSerialNumber(CertificateSerialNumber certificateSerialNumber) {
        setFieldAs(TBSCertificateField.SERIAL_NUMBER, certificateSerialNumber);
    }

    public AlgorithmIdentifier getSignature() {
        return getFieldAs(TBSCertificateField.SIGNATURE, AlgorithmIdentifier.class);
    }

    public void setSignature(AlgorithmIdentifier signature) {
        setFieldAs(TBSCertificateField.SIGNATURE, signature);
    }

    public Name getIssuer() {
        return getFieldAs(TBSCertificateField.ISSUER, Name.class);
    }

    public void setIssuer(Name attCertIssuer) {
        setFieldAs(TBSCertificateField.ISSUER, attCertIssuer);
    }

    public AttCertValidityPeriod getValidity() {
        return getFieldAs(TBSCertificateField.VALIDITY, AttCertValidityPeriod.class);
    }

    public void setValidity(AttCertValidityPeriod validity) {
        setFieldAs(TBSCertificateField.VALIDITY, validity);
    }

    public Name getSubject() {
        return getFieldAs(TBSCertificateField.SUBJECT, Name.class);
    }

    public void setSubject(Name subject) {
        setFieldAs(TBSCertificateField.SUBJECT, subject);
    }

    public SubjectPublicKeyInfo getSubjectPublicKeyInfo() {
        return getFieldAs(TBSCertificateField.SUBJECT_PUBLIC_KEY_INFO, SubjectPublicKeyInfo.class);
    }

    public void setSubjectPublicKeyInfo(SubjectPublicKeyInfo subjectPublicKeyInfo) {
        setFieldAs(TBSCertificateField.SUBJECT_PUBLIC_KEY_INFO, subjectPublicKeyInfo);
    }

    public byte[] getIssuerUniqueID() {
        return getFieldAs(TBSCertificateField.ISSUER_UNIQUE_ID, Asn1BitString.class).getValue();
    }

    public void setIssuerUniqueId(byte[] issuerUniqueId) {
        setFieldAs(TBSCertificateField.ISSUER_UNIQUE_ID, new Asn1BitString(issuerUniqueId));
    }

    public byte[] getSubjectUniqueId() {
        return getFieldAs(TBSCertificateField.ISSUER_UNIQUE_ID, Asn1BitString.class).getValue();
    }

    public void setSubjectUniqueId(byte[] issuerUniqueId) {
        setFieldAs(TBSCertificateField.SUBJECT_UNIQUE_ID, new Asn1BitString(issuerUniqueId));
    }

    public Extensions getExtensions() {
        return getFieldAs(TBSCertificateField.EXTENSIONS, Extensions.class);
    }

    public void setExtensions(Extensions extensions) {
        setFieldAs(TBSCertificateField.EXTENSIONS, extensions);
    }
}
