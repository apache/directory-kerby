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

import org.apache.kerby.asn1.type.Asn1Boolean;
import org.apache.kerby.asn1.type.Asn1FieldInfo;
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
    private static final int EXTN_ID = 0;
    private static final int CRITICAL = 1;
    private static final int EXTN_VALUE = 2;

    static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[] {
        new Asn1FieldInfo(EXTN_ID, Asn1ObjectIdentifier.class),
        new Asn1FieldInfo(CRITICAL, Asn1Boolean.class),
        new Asn1FieldInfo(EXTN_VALUE, Asn1OctetString.class)
    };

    public Extension() {
        super(fieldInfos);
    }

    public Asn1ObjectIdentifier getExtnId() {
        return getFieldAs(EXTN_ID, Asn1ObjectIdentifier.class);
    }

    public void setExtnId(Asn1ObjectIdentifier extnId) {
        setFieldAs(EXTN_ID, extnId);
    }

    public boolean getCritical() {
        return getFieldAs(CRITICAL, Asn1Boolean.class).getValue();
    }

    public void setCritical(boolean critical) {
        setFieldAs(CRITICAL, new Asn1Boolean(critical));
    }

    public byte[] getExtnValue() {
        return getFieldAsOctets(EXTN_VALUE);
    }

    public void setValue(byte[] value) {
        setFieldAsOctets(EXTN_VALUE, value);
    }
}
