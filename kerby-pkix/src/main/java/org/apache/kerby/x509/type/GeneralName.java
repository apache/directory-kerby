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
    protected enum GeneralNameField implements EnumType {
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
        new ImplicitField(GeneralNameField.OTHER_NAME, OtherName.class),
        new ImplicitField(GeneralNameField.RFC822_NAME, Asn1IA5String.class),
        new ImplicitField(GeneralNameField.DNS_NAME, Asn1IA5String.class),
        // ORAddress is to be defined.
        new ImplicitField(GeneralNameField.X400_ADDRESS, Asn1Any.class),
        new ExplicitField(GeneralNameField.DIRECTORY_NAME, Name.class),
        new ImplicitField(GeneralNameField.EDI_PARTY_NAME, EDIPartyName.class),
        new ImplicitField(GeneralNameField.UNIFORM_RESOURCE_IDENTIFIER, Asn1IA5String.class),
        new ImplicitField(GeneralNameField.IP_ADDRESS, Asn1OctetString.class),
        new ImplicitField(GeneralNameField.REGISTERED_ID, Asn1ObjectIdentifier.class)
    };

    public GeneralName() {
        super(fieldInfos);
    }

    public OtherName getOtherName() {
        return getChoiceValueAs(GeneralNameField.OTHER_NAME, OtherName.class);
    }

    public void setOtherName(OtherName otherName) {
        setChoiceValue(GeneralNameField.OTHER_NAME, otherName);
    }

    public Asn1IA5String getRfc822Name() {
        return getChoiceValueAs(GeneralNameField.RFC822_NAME, Asn1IA5String.class);
    }

    public void setRfc822Name(Asn1IA5String rfc822Name) {
        setChoiceValue(GeneralNameField.RFC822_NAME, rfc822Name);
    }

    public Asn1IA5String getDNSName() {
        return getChoiceValueAs(GeneralNameField.DNS_NAME, Asn1IA5String.class);
    }

    public void setDNSName(Asn1IA5String dnsName) {
        setChoiceValue(GeneralNameField.DNS_NAME, dnsName);
    }

    public Asn1Any getX400Address() {
        return getChoiceValueAs(GeneralNameField.X400_ADDRESS, Asn1Any.class);
    }

    public void setX400Address(Asn1Any x400Address) {
        setChoiceValue(GeneralNameField.X400_ADDRESS, x400Address);
    }

    public Name getDirectoryName() {
        return getChoiceValueAs(GeneralNameField.DIRECTORY_NAME, Name.class);
    }

    public void setDirectoryName(Name directoryName) {
        setChoiceValue(GeneralNameField.DIRECTORY_NAME, directoryName);
    }

    public EDIPartyName getEdiPartyName() {
        return getChoiceValueAs(GeneralNameField.EDI_PARTY_NAME, EDIPartyName.class);
    }

    public void setEdiPartyName(EDIPartyName ediPartyName) {
        setChoiceValue(GeneralNameField.EDI_PARTY_NAME, ediPartyName);
    }

    public Asn1IA5String getUniformResourceIdentifier() {
        return getChoiceValueAs(GeneralNameField.UNIFORM_RESOURCE_IDENTIFIER, Asn1IA5String.class);
    }

    public void setUniformResourceIdentifier(Asn1IA5String uniformResourceIdentifier) {
        setChoiceValue(GeneralNameField.UNIFORM_RESOURCE_IDENTIFIER, uniformResourceIdentifier);
    }

    public byte[] getIPAddress() {
        return getChoiceValueAsOctets(GeneralNameField.IP_ADDRESS);
    }

    public void setIpAddress(byte[] ipAddress) {
        setChoiceValueAsOctets(GeneralNameField.IP_ADDRESS, ipAddress);
    }

    public Asn1ObjectIdentifier getRegisteredID() {
        return getChoiceValueAs(GeneralNameField.REGISTERED_ID, Asn1ObjectIdentifier.class);
    }

    public void setRegisteredID(Asn1ObjectIdentifier registeredID) {
        setChoiceValue(GeneralNameField.REGISTERED_ID, registeredID);
    }
}
