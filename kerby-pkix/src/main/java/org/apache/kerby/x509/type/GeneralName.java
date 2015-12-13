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
import org.apache.kerby.asn1.ExplicitField;
import org.apache.kerby.asn1.ImplicitField;
import org.apache.kerby.asn1.type.Asn1Any;
import org.apache.kerby.asn1.type.Asn1Choice;
import org.apache.kerby.asn1.type.Asn1IA5String;
import org.apache.kerby.asn1.type.Asn1ObjectIdentifier;
import org.apache.kerby.asn1.type.Asn1OctetString;
import org.apache.kerby.x500.type.Name;

import static org.apache.kerby.x509.type.GeneralName.MyEnum.DIRECTORY_NAME;
import static org.apache.kerby.x509.type.GeneralName.MyEnum.DNS_NAME;
import static org.apache.kerby.x509.type.GeneralName.MyEnum.EDI_PARTY_NAME;
import static org.apache.kerby.x509.type.GeneralName.MyEnum.IP_ADDRESS;
import static org.apache.kerby.x509.type.GeneralName.MyEnum.OTHER_NAME;
import static org.apache.kerby.x509.type.GeneralName.MyEnum.REGISTERED_ID;
import static org.apache.kerby.x509.type.GeneralName.MyEnum.RFC822_NAME;
import static org.apache.kerby.x509.type.GeneralName.MyEnum.UNIFORM_RESOURCE_IDENTIFIER;
import static org.apache.kerby.x509.type.GeneralName.MyEnum.X400_ADDRESS;

/**
 *
 * <pre>
 * GeneralName ::= CHOICE {
 *      otherName                       [0]     OtherName,
 *      rfc822Name                      [1]     IA5String,
 *      dNSName                         [2]     IA5String,
 *      x400Address                     [3]     ORAddress,
 *      directoryName                   [4]     Name,
 *      ediPartyName                    [5]     EDIPartyName,
 *      uniformResourceIdentifier       [6]     IA5String,
 *      iPAddress                       [7]     OCTET STRING,
 *      registeredID                    [8]     OBJECT IDENTIFIER
 *  }
 * </pre>
 */
public class GeneralName extends Asn1Choice {
    protected enum MyEnum implements EnumType {
        OTHER_NAME,
        RFC822_NAME,
        DNS_NAME,
        X400_ADDRESS,
        DIRECTORY_NAME,
        EDI_PARTY_NAME,
        UNIFORM_RESOURCE_IDENTIFIER,
        IP_ADDRESS,
        REGISTERED_ID;

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
        new ImplicitField(OTHER_NAME, OtherName.class),
        new ImplicitField(RFC822_NAME, Asn1IA5String.class),
        new ImplicitField(DNS_NAME, Asn1IA5String.class),
        // ORAddress is to be defined.
        new ImplicitField(X400_ADDRESS, Asn1Any.class),
        new ExplicitField(DIRECTORY_NAME, Name.class),
        new ImplicitField(EDI_PARTY_NAME, EDIPartyName.class),
        new ImplicitField(UNIFORM_RESOURCE_IDENTIFIER, Asn1IA5String.class),
        new ImplicitField(IP_ADDRESS, Asn1OctetString.class),
        new ImplicitField(REGISTERED_ID, Asn1ObjectIdentifier.class)
    };

    public GeneralName() {
        super(fieldInfos);
    }

    public OtherName getOtherName() {
        return getChoiceValueAs(OTHER_NAME, OtherName.class);
    }

    public void setOtherName(OtherName otherName) {
        setChoiceValue(OTHER_NAME, otherName);
    }

    public Asn1IA5String getRfc822Name() {
        return getChoiceValueAs(RFC822_NAME, Asn1IA5String.class);
    }

    public void setRfc822Name(Asn1IA5String rfc822Name) {
        setChoiceValue(RFC822_NAME, rfc822Name);
    }

    public Asn1IA5String getDNSName() {
        return getChoiceValueAs(DNS_NAME, Asn1IA5String.class);
    }

    public void setDNSName(Asn1IA5String dnsName) {
        setChoiceValue(DNS_NAME, dnsName);
    }

    public Asn1Any getX400Address() {
        return getChoiceValueAs(X400_ADDRESS, Asn1Any.class);
    }

    public void setX400Address(Asn1Any x400Address) {
        setChoiceValue(X400_ADDRESS, x400Address);
    }

    public Name getDirectoryName() {
        return getChoiceValueAs(DIRECTORY_NAME, Name.class);
    }

    public void setDirectoryName(Name directoryName) {
        setChoiceValue(DIRECTORY_NAME, directoryName);
    }

    public EDIPartyName getEdiPartyName() {
        return getChoiceValueAs(EDI_PARTY_NAME, EDIPartyName.class);
    }

    public void setEdiPartyName(EDIPartyName ediPartyName) {
        setChoiceValue(EDI_PARTY_NAME, ediPartyName);
    }

    public Asn1IA5String getUniformResourceIdentifier() {
        return getChoiceValueAs(UNIFORM_RESOURCE_IDENTIFIER, Asn1IA5String.class);
    }

    public void setUniformResourceIdentifier(Asn1IA5String uniformResourceIdentifier) {
        setChoiceValue(UNIFORM_RESOURCE_IDENTIFIER, uniformResourceIdentifier);
    }

    public byte[] getIPAddress() {
        return getChoiceValueAsOctets(IP_ADDRESS);
    }

    public void setIpAddress(byte[] ipAddress) {
        setChoiceValueAsOctets(IP_ADDRESS, ipAddress);
    }

    public Asn1ObjectIdentifier getRegisteredID() {
        return getChoiceValueAs(REGISTERED_ID, Asn1ObjectIdentifier.class);
    }

    public void setRegisteredID(Asn1ObjectIdentifier registeredID) {
        setChoiceValue(REGISTERED_ID, registeredID);
    }
}
