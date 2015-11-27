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

import org.apache.kerby.asn1.type.Asn1FieldInfo;
import org.apache.kerby.asn1.type.Asn1Integer;
import org.apache.kerby.asn1.type.Asn1SequenceType;
import org.apache.kerby.x500.type.Name;

/**
 * Ref. RFC5652
 * <pre>
 * IssuerAndSerialNumber ::= SEQUENCE {
 *     issuer Name,
 *     serialNumber CertificateSerialNumber
 * }
 *
 * CertificateSerialNumber ::= INTEGER  -- See RFC 5280
 * </pre>
 */
public class IssuerAndSerialNumber extends Asn1SequenceType {
    private static final int ISSUER = 0;
    private static final int SERIAL_NUMBER = 1;

    static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[]{
        new Asn1FieldInfo(ISSUER, Name.class),
        new Asn1FieldInfo(SERIAL_NUMBER, Asn1Integer.class)
    };

    public IssuerAndSerialNumber() {
        super(fieldInfos);
    }

    public Name getIssuer() {
        return getFieldAs(ISSUER, Name.class);
    }

    public void setIssuer(Name name) {
        setFieldAs(ISSUER, name);
    }

    public Asn1Integer getSerialNumber() {
        return getFieldAs(SERIAL_NUMBER, Asn1Integer.class);
    }

    public void setSerialNumber(int serialNumber) {
        setFieldAsInt(SERIAL_NUMBER, serialNumber);
    }
}
