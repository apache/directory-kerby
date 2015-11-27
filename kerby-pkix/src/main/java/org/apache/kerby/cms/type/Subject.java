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
import org.apache.kerby.asn1.type.ExplicitField;
import org.apache.kerby.x509.type.GeneralNames;
import org.apache.kerby.x509.type.IssuerSerial;

/**
 * subject CHOICE {
 *   baseCertificateID [0] IssuerSerial,
 *     -- associated with a Public Key Certificate
 *   subjectName [1] GeneralNames
 *     -- associated with a name
 * },
 *
 */
public class Subject extends Asn1Choice {
    private static final int BASE_CERTIFICATE_ID = 0;
    private static final int SUBJECT_NAME = 1;

    static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[]{
            new ExplicitField(BASE_CERTIFICATE_ID, IssuerSerial.class),
            new ExplicitField(SUBJECT_NAME, GeneralNames.class)
    };

    public Subject() {
        super(fieldInfos);
    }

    public IssuerSerial getBaseCertificateID() {
        return getFieldAs(BASE_CERTIFICATE_ID, IssuerSerial.class);
    }

    public void setBaseCertificateID(IssuerSerial baseCertificateID) {
        setFieldAs(BASE_CERTIFICATE_ID, baseCertificateID);
    }

    public GeneralNames getSubjectName() {
        return getFieldAs(SUBJECT_NAME, GeneralNames.class);
    }

    public void setSubjectName(GeneralNames subjectName) {
        setFieldAs(SUBJECT_NAME, subjectName);
    }
}
