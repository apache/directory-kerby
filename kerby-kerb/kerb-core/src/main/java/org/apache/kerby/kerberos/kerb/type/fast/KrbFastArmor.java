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
package org.apache.kerby.kerberos.kerb.type.fast;

import org.apache.kerby.asn1.Asn1FieldInfo;
import org.apache.kerby.asn1.EnumType;
import org.apache.kerby.asn1.ExplicitField;
import org.apache.kerby.asn1.type.Asn1Integer;
import org.apache.kerby.asn1.type.Asn1OctetString;
import org.apache.kerby.kerberos.kerb.type.KrbSequenceType;

/**
 KrbFastArmor ::= SEQUENCE {
     armor-type   [0] Int32,
     -- Type of the armor.
     armor-value  [1] OCTET STRING,
     -- Value of the armor.
 }
 */
public class KrbFastArmor extends KrbSequenceType {
    protected enum KrbFastArmorField implements EnumType {
        ARMOR_TYPE,
        ARMOR_VALUE;

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
            new ExplicitField(KrbFastArmorField.ARMOR_TYPE, Asn1Integer.class),
            new ExplicitField(KrbFastArmorField.ARMOR_VALUE, Asn1OctetString.class)
    };

    public KrbFastArmor() {
        super(fieldInfos);
    }

    public ArmorType getArmorType() {
        Integer value = getFieldAsInteger(KrbFastArmorField.ARMOR_TYPE);
        return ArmorType.fromValue(value);
    }

    public void setArmorType(ArmorType armorType) {
        setFieldAsInt(KrbFastArmorField.ARMOR_TYPE, armorType.getValue());
    }

    public byte[] getArmorValue() {
        return getFieldAsOctets(KrbFastArmorField.ARMOR_VALUE);
    }

    public void setArmorValue(byte[] armorValue) {
        setFieldAsOctets(KrbFastArmorField.ARMOR_VALUE, armorValue);
    }
}
