package org.haox.kerb.spec.pa;

import org.haox.asn1.type.Asn1FieldInfo;
import org.haox.asn1.type.Asn1Integer;
import org.haox.asn1.type.Asn1OctetString;
import org.haox.kerb.spec.KrbSequenceType;

/**
 PA-AUTHENTICATION-SET-ELEM ::= SEQUENCE {
     pa-type      [0] Int32,
     -- same as padata-type.
     pa-hint      [1] OCTET STRING OPTIONAL,
     pa-value     [2] OCTET STRING OPTIONAL
 }
 */
public class PaAuthenticationSetElem extends KrbSequenceType {
    private static int PA_TYPE = 0;
    private static int PA_HINT = 1;
    private static int PA_VALUE = 2;

    static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[] {
            new Asn1FieldInfo(PA_TYPE, Asn1Integer.class),
            new Asn1FieldInfo(PA_HINT, Asn1OctetString.class),
            new Asn1FieldInfo(PA_VALUE, Asn1OctetString.class)
    };

    public PaAuthenticationSetElem() {
        super(fieldInfos);
    }

    public PaDataType getPaType() {
        Integer value = getFieldAsInteger(PA_TYPE);
        return PaDataType.fromValue(value);
    }

    public void setPaType(PaDataType paDataType) {
        setFieldAsInt(PA_TYPE, paDataType.getValue());
    }

    public byte[] getPaHint() {
        return getFieldAsOctets(PA_HINT);
    }

    public void setPaHint(byte[] paHint) {
        setFieldAsOctets(PA_HINT, paHint);
    }

    public byte[] getPaValue() {
        return getFieldAsOctets(PA_VALUE);
    }

    public void setPaValue(byte[] paDataValue) {
        setFieldAsOctets(PA_VALUE, paDataValue);
    }
}
