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

import org.apache.kerby.asn1.Asn1FieldInfo;
import org.apache.kerby.asn1.EnumType;
import org.apache.kerby.asn1.ExplicitField;
import org.apache.kerby.asn1.type.Asn1Choice;
import org.apache.kerby.x509.type.SubjectKeyIdentifier;

import static org.apache.kerby.cms.type.OriginatorIdentifierOrKey.MyEnum.*;

/**
 * OriginatorIdentifierOrKey ::= CHOICE {
 *   issuerAndSerialNumber IssuerAndSerialNumber,
 *   subjectKeyIdentifier [0] SubjectKeyIdentifier,
 *   originatorKey [1] OriginatorPublicKey }
 */
public class OriginatorIdentifierOrKey extends Asn1Choice {
    protected enum MyEnum implements EnumType {
        ISSUER_AND_SERIAL_NUMBER,
        SUBJECT_KEY_IDENTIFIER,
        ORIGINATOR_KEY;

        @Override
        public int getValue() {
            return ordinal();
        }

        @Override
        public String getName() {
            return name();
        }
    }

    static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[]{
            new Asn1FieldInfo(ISSUER_AND_SERIAL_NUMBER, IssuerAndSerialNumber.class),
            new ExplicitField(SUBJECT_KEY_IDENTIFIER, 0, SubjectKeyIdentifier.class),
            new ExplicitField(ORIGINATOR_KEY, 1, OriginatorPublicKey.class)
    };

    public OriginatorIdentifierOrKey() {
        super(fieldInfos);
    }

    public IssuerAndSerialNumber getIssuerAndSerialNumber() {
        return getChoiceValueAs(ISSUER_AND_SERIAL_NUMBER, IssuerAndSerialNumber.class);
    }

    public void setIssuerAndSerialNumber(IssuerAndSerialNumber issuerAndSerialNumber) {
        setChoiceValue(ISSUER_AND_SERIAL_NUMBER, issuerAndSerialNumber);
    }

    public SubjectKeyIdentifier getSubjectKeyIdentifier() {
        return getChoiceValueAs(SUBJECT_KEY_IDENTIFIER, SubjectKeyIdentifier.class);
    }

    public void setSubjectKeyIdentifier(SubjectKeyIdentifier subjectKeyIdentifier) {
        setChoiceValue(SUBJECT_KEY_IDENTIFIER, subjectKeyIdentifier);
    }

    public OriginatorPublicKey getOriginatorPublicKey() {
        return getChoiceValueAs(ORIGINATOR_KEY, OriginatorPublicKey.class);
    }

    public void setOriginatorPublicKey(OriginatorPublicKey originatorPublicKey) {
        setChoiceValue(ORIGINATOR_KEY, originatorPublicKey);
    }
}
