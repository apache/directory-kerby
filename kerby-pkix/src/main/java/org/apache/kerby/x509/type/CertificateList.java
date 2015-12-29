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
 *
 * RFC-2459:
 * <pre>
 * CertificateList  ::=  SEQUENCE  {
 *      tbsCertList          TBSCertList,
 *      signatureAlgorithm   AlgorithmIdentifier,
 *      signatureValue       BIT STRING
 * }
 * </pre>
 */
public class CertificateList extends Asn1SequenceType {
    protected enum CertificateListField implements EnumType {
        TBS_CERT_LIST,
        SIGNATURE_ALGORITHMS,
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
        new Asn1FieldInfo(CertificateListField.TBS_CERT_LIST, TBSCertList.class),
        new Asn1FieldInfo(CertificateListField.SIGNATURE_ALGORITHMS, AlgorithmIdentifier.class),
        new Asn1FieldInfo(CertificateListField.SIGNATURE_VALUE, Asn1BitString.class)
    };

    public CertificateList() {
        super(fieldInfos);
    }

    public TBSCertList getTBSCertList() {
        return getFieldAs(CertificateListField.TBS_CERT_LIST, TBSCertList.class);
    }

    public void setTBSCertList(TBSCertList tbsCertList) {
        setFieldAs(CertificateListField.TBS_CERT_LIST, tbsCertList);
    }

    public AlgorithmIdentifier getSignatureAlgorithm() {
        return getFieldAs(CertificateListField.SIGNATURE_ALGORITHMS, AlgorithmIdentifier.class);
    }

    public void setSignatureAlgorithms(AlgorithmIdentifier signatureAlgorithms) {
        setFieldAs(CertificateListField.SIGNATURE_ALGORITHMS, signatureAlgorithms);
    }

    public Asn1BitString getSignature() {
        return getFieldAs(CertificateListField.SIGNATURE_VALUE, Asn1BitString.class);
    }

    public void setSignatureValue(Asn1BitString signatureValue) {
        setFieldAs(CertificateListField.SIGNATURE_VALUE, signatureValue);
    }
}
