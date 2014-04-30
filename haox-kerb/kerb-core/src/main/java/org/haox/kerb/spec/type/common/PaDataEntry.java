package org.haox.kerb.spec.type.common;

import org.haox.asn1.type.Asn1FieldInfo;
import org.haox.asn1.type.Asn1Integer;
import org.haox.asn1.type.Asn1OctetString;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.KrbSequenceType;

/**
 PA-DATA         ::= SEQUENCE {
 -- NOTE: first tag is [1], not [0]
 padata-type     [1] Int32,
 padata-value    [2] OCTET STRING -- might be encoded AP-REQ
 }
 */
public class PaDataEntry extends KrbSequenceType {
    private static int PADATA_TYPE = 0;
    private static int PADATA_VALUE = 1;

    static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[] {
            new Asn1FieldInfo(PADATA_TYPE, 1, Asn1Integer.class),
            new Asn1FieldInfo(PADATA_VALUE, 2, Asn1OctetString.class)
    };

    public PaDataEntry() {
        super(fieldInfos);
    }

    public PaDataType getPaDataType() throws KrbException {
        Integer value = getFieldAsInteger(PADATA_TYPE);
        return PaDataType.fromValue(value);
    }

    public void setPaDataType(PaDataType paDataType) throws KrbException {
        setFieldAsInt(PADATA_TYPE, paDataType.getValue());
    }

    public byte[] getPaDataValue() throws KrbException {
        return getFieldAsOctetBytes(PADATA_VALUE);
    }

    public void setPaDataValue(byte[] paDataValue) throws KrbException {
        setFieldAsOctetBytes(PADATA_VALUE, paDataValue);
    }
}
