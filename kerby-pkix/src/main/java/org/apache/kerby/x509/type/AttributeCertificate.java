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
import org.apache.kerby.asn1.type.Asn1SequenceType;

/**
 * <pre>
 *  AttributeCertificate ::= SEQUENCE {
 *       acinfo               AttributeCertificateInfo,
 *       signatureAlgorithm   AlgorithmIdentifier,
 *       signatureValue       BIT STRING
 *  }
 * </pre>
 */
public class AttributeCertificate extends Asn1SequenceType {
    protected enum AttributeCertificateField implements EnumType {
        ACI_INFO,
        SIGNATURE_ALGORITHM,
        SIGNATURE_VALUE;
        
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
        new Asn1FieldInfo(AttributeCertificateField.ACI_INFO, AttributeCertificateInfo.class),
        new Asn1FieldInfo(AttributeCertificateField.SIGNATURE_ALGORITHM, AlgorithmIdentifier.class),
        new Asn1FieldInfo(AttributeCertificateField.SIGNATURE_VALUE, Asn1BitString.class)
    };

    public AttributeCertificate() {
        super(fieldInfos);
    }

    public AttributeCertificateInfo getAcinfo() {
        return getFieldAs(AttributeCertificateField.ACI_INFO, AttributeCertificateInfo.class);
    }

    public void setAciInfo(AttributeCertificateInfo aciInfo) {
        setFieldAs(AttributeCertificateField.ACI_INFO, aciInfo);
    }

    public AlgorithmIdentifier getSignatureAlgorithm() {
        return getFieldAs(AttributeCertificateField.SIGNATURE_ALGORITHM, AlgorithmIdentifier.class);
    }

    public void setSignatureAlgorithm(AlgorithmIdentifier signatureAlgorithm) {
        setFieldAs(AttributeCertificateField.SIGNATURE_ALGORITHM, signatureAlgorithm);
    }

    public Asn1BitString getSignatureValue() {
        return getFieldAs(AttributeCertificateField.SIGNATURE_VALUE, Asn1BitString.class);
    }

    public void setSignatureValue(Asn1BitString signatureValue) {
        setFieldAs(AttributeCertificateField.SIGNATURE_VALUE, signatureValue);
    }
}
