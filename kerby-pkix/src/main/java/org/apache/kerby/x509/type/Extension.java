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
import org.apache.kerby.asn1.type.Asn1Boolean;
import org.apache.kerby.asn1.type.Asn1ObjectIdentifier;
import org.apache.kerby.asn1.type.Asn1OctetString;
import org.apache.kerby.asn1.type.Asn1SequenceType;

/**
 * Ref. X.509 V3 extension
 * <pre>
 *     Extensions        ::=   SEQUENCE SIZE (1..MAX) OF Extension
 *
 *     Extension         ::=   SEQUENCE {
 *        extnId            EXTENSION.&amp;id ({ExtensionSet}),
 *        critical          BOOLEAN DEFAULT FALSE,
 *        extnValue         OCTET STRING }
 * </pre>
 */
public class Extension extends Asn1SequenceType {
    protected enum ExtensionField implements EnumType {
        EXTN_ID,
        CRITICAL,
        EXTN_VALUE;

        @Override
        public int getValue() {
            return ordinal();
        }

        @Override
        public String getName() {
            return name();
        }
    }

    private final boolean critical = false;

    static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[] {
        new Asn1FieldInfo(ExtensionField.EXTN_ID, Asn1ObjectIdentifier.class),
        new Asn1FieldInfo(ExtensionField.CRITICAL, Asn1Boolean.class),
        new Asn1FieldInfo(ExtensionField.EXTN_VALUE, Asn1OctetString.class)
    };

    public Extension() {
        super(fieldInfos);
        setCritical(critical);
    }

    public Asn1ObjectIdentifier getExtnId() {
        return getFieldAs(ExtensionField.EXTN_ID, Asn1ObjectIdentifier.class);
    }

    public void setExtnId(Asn1ObjectIdentifier extnId) {
        setFieldAs(ExtensionField.EXTN_ID, extnId);
    }

    public boolean getCritical() {
        return getFieldAs(ExtensionField.CRITICAL, Asn1Boolean.class).getValue();
    }

    public void setCritical(boolean critical) {
        setFieldAs(ExtensionField.CRITICAL, new Asn1Boolean(critical));
    }

    public byte[] getExtnValue() {
        return getFieldAsOctets(ExtensionField.EXTN_VALUE);
    }

    public void setExtnValue(byte[] value) {
        setFieldAsOctets(ExtensionField.EXTN_VALUE, value);
    }
}
