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
 *  Certificate ::= SEQUENCE {
 *      tbsCertificate          TBSCertificate,
 *      signatureAlgorithm      AlgorithmIdentifier,
 *      signature               BIT STRING
 *  }
 * </pre>
 */
public class Certificate extends Asn1SequenceType {
    protected enum CertificateField implements EnumType {
        TBS_CERTIFICATE,
        SIGNATURE_ALGORITHM,
        SIGNATURE;

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
        new Asn1FieldInfo(CertificateField.TBS_CERTIFICATE, TBSCertificate.class),
        new Asn1FieldInfo(CertificateField.SIGNATURE_ALGORITHM, AlgorithmIdentifier.class),
        new Asn1FieldInfo(CertificateField.SIGNATURE, Asn1BitString.class)
    };

    public Certificate() {
        super(fieldInfos);
    }

    public TBSCertificate getTBSCertificate() {
        return getFieldAs(CertificateField.TBS_CERTIFICATE, TBSCertificate.class);
    }

    public void setTbsCertificate(TBSCertificate tbsCertificate) {
        setFieldAs(CertificateField.TBS_CERTIFICATE, tbsCertificate);
    }

    public AlgorithmIdentifier getSignatureAlgorithm() {
        return getFieldAs(CertificateField.SIGNATURE_ALGORITHM, AlgorithmIdentifier.class);
    }

    public void setSignatureAlgorithm(AlgorithmIdentifier signatureAlgorithm) {
        setFieldAs(CertificateField.SIGNATURE_ALGORITHM, signatureAlgorithm);
    }

    public Asn1BitString getSignature() {
        return getFieldAs(CertificateField.SIGNATURE, Asn1BitString.class);
    }

    public void setSignature(Asn1BitString signature) {
        setFieldAs(CertificateField.SIGNATURE, signature);
    }
}
