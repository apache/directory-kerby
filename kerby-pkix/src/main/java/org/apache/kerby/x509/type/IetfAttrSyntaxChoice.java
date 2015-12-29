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
import org.apache.kerby.asn1.type.Asn1Choice;
import org.apache.kerby.asn1.type.Asn1ObjectIdentifier;
import org.apache.kerby.asn1.type.Asn1OctetString;

/**
 * Ref. RFC3281
 * <pre>
 *  IetfAttrSyntax ::= SEQUENCE {
 *    policyAuthority [0] GeneralNames OPTIONAL,
 *    values SEQUENCE OF CHOICE {
 *      octets OCTET STRING,
 *      oid OBJECT IDENTIFIER,
 *      string UTF8String
 *    }
 *  }
 * </pre>
 */
public class IetfAttrSyntaxChoice extends Asn1Choice {
    protected enum IetfAttrSyntaxChoiceField implements EnumType {
        OCTETS,
        OID,
        UTF8;

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
        new Asn1FieldInfo(IetfAttrSyntaxChoiceField.OCTETS, Asn1OctetString.class),
        new Asn1FieldInfo(IetfAttrSyntaxChoiceField.OID, Asn1ObjectIdentifier.class),
        new Asn1FieldInfo(IetfAttrSyntaxChoiceField.UTF8, Asn1ObjectIdentifier.class)
    };

    public IetfAttrSyntaxChoice() {
        super(fieldInfos);
    }

    public Asn1OctetString getOctets() {
        return getChoiceValueAs(IetfAttrSyntaxChoiceField.OCTETS, Asn1OctetString.class);
    }

    public void setOctets(Asn1OctetString octets) {
        setChoiceValue(IetfAttrSyntaxChoiceField.OCTETS, octets);
    }

    public Asn1ObjectIdentifier getOid() {
        return getChoiceValueAs(IetfAttrSyntaxChoiceField.OID, Asn1ObjectIdentifier.class);
    }

    public void setOid(Asn1ObjectIdentifier oid) {
        setChoiceValue(IetfAttrSyntaxChoiceField.OID, oid);
    }

    public Asn1ObjectIdentifier getUtf8() {
        return getChoiceValueAs(IetfAttrSyntaxChoiceField.UTF8, Asn1ObjectIdentifier.class);
    }

    public void setUtf8(Asn1ObjectIdentifier utf8) {
        setChoiceValue(IetfAttrSyntaxChoiceField.UTF8, utf8);
    }
}
