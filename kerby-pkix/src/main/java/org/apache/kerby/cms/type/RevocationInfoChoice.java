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
package org.apache.kerby.cms.type;

import org.apache.kerby.asn1.type.Asn1Choice;
import org.apache.kerby.asn1.type.Asn1FieldInfo;
import org.apache.kerby.asn1.type.ImplicitField;

/**
 * RevocationInfoChoice ::= CHOICE {
 *   crl CertificateList,
 *   other [1] IMPLICIT OtherRevocationInfoFormat
 * }
 */
public class RevocationInfoChoice extends Asn1Choice {
    private static final int CRL = 0;
    private static final int OTHER = 1;

    static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[] {
            new Asn1FieldInfo(CRL, CertificateList.class),
            new ImplicitField(OTHER, 1, OtherRevocationInfoFormat.class)
    };

    public RevocationInfoChoice() {
        super(fieldInfos);
    }

    public CertificateList getCRL() {
        return getFieldAs(CRL, CertificateList.class);
    }

    public void setCRL(CertificateList crl) {
        setFieldAs(CRL, crl);
    }

    public OtherRevocationInfoFormat getOther() {
        return getFieldAs(OTHER, OtherRevocationInfoFormat.class);
    }

    public void setOther(OtherRevocationInfoFormat other) {
        setFieldAs(OTHER, other);
    }
}
