package org.haox.kerb.spec.fast;

import org.apache.haox.asn1.type.Asn1FieldInfo;
import org.apache.haox.asn1.type.Asn1Integer;
import org.apache.haox.asn1.type.Asn1OctetString;
import org.haox.kerb.spec.KrbSequenceType;

/**
 KrbFastArmor ::= SEQUENCE {
     armor-type   [0] Int32,
     -- Type of the armor.
     armor-value  [1] OCTET STRING,
     -- Value of the armor.
 }
 */
public class KrbFastArmor extends KrbSequenceType {
    private static int ARMOR_TYPE = 0;
    private static int ARMOR_VALUE = 1;

    static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[] {
            new Asn1FieldInfo(ARMOR_TYPE, Asn1Integer.class),
            new Asn1FieldInfo(ARMOR_VALUE, Asn1OctetString.class)
    };

    public KrbFastArmor() {
        super(fieldInfos);
    }

    public ArmorType getArmorType() {
        Integer value = getFieldAsInteger(ARMOR_TYPE);
        return ArmorType.fromValue(value);
    }

    public void setArmorType(ArmorType armorType) {
        setFieldAsInt(ARMOR_TYPE, armorType.getValue());
    }

    public byte[] getArmorValue() {
        return getFieldAsOctets(ARMOR_VALUE);
    }

    public void setArmorValue(byte[] armorValue) {
        setFieldAsOctets(ARMOR_VALUE, armorValue);
    }
}
