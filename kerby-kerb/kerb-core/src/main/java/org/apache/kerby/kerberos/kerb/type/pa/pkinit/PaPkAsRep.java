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
package org.apache.kerby.kerberos.kerb.type.pa.pkinit;

import org.apache.kerby.asn1.Asn1FieldInfo;
import org.apache.kerby.asn1.EnumType;
import org.apache.kerby.asn1.ExplicitField;
import org.apache.kerby.asn1.ImplicitField;
import org.apache.kerby.asn1.type.Asn1Choice;
import org.apache.kerby.asn1.type.Asn1OctetString;

/**
 PA-PK-AS-REP ::= CHOICE {
    dhInfo                  [0] DhRepInfo,
    encKeyPack              [1] IMPLICIT OCTET STRING,
 }
 */
public class PaPkAsRep extends Asn1Choice {
    protected enum PaPkAsRepField implements EnumType {
        DH_INFO,
        ENCKEY_PACK;

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
            new ExplicitField(PaPkAsRepField.DH_INFO, DhRepInfo.class),
            new ImplicitField(PaPkAsRepField.ENCKEY_PACK, Asn1OctetString.class)
    };

    public PaPkAsRep() {
        super(fieldInfos);
    }

    public DhRepInfo getDHRepInfo() {
        return getChoiceValueAs(PaPkAsRepField.DH_INFO, DhRepInfo.class);
    }

    public void setDHRepInfo(DhRepInfo dhRepInfo) {
        setChoiceValue(PaPkAsRepField.DH_INFO, dhRepInfo);
    }

    public byte[] getEncKeyPack() {
        return getChoiceValueAsOctets(PaPkAsRepField.ENCKEY_PACK);
    }

    public void setEncKeyPack(byte[] encKeyPack) {
        setChoiceValueAsOctets(PaPkAsRepField.ENCKEY_PACK, encKeyPack);
    }
}
