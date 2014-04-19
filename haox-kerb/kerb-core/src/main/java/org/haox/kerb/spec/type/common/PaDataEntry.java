package org.haox.kerb.spec.type.common;

import org.haox.asn1.type.AbstractSequenceType;
import org.haox.asn1.type.Asn1Integer;
import org.haox.asn1.type.Asn1OctetString;
import org.haox.asn1.type.Asn1Tag;
import org.haox.kerb.spec.KrbException;

/**
 PA-DATA         ::= SEQUENCE {
 -- NOTE: first tag is [1], not [0]
 padata-type     [1] Int32,
 padata-value    [2] OCTET STRING -- might be encoded AP-REQ
 }
 */
public class PaDataEntry extends AbstractSequenceType {
    private static int PADATA_TYPE = 0;
    private static int PADATA_VALUE = 1;

    static Asn1Tag[] tags = new Asn1Tag[] {
            new Asn1Tag(PADATA_TYPE, 1, Asn1Integer.class),
            new Asn1Tag(PADATA_VALUE, 2, Asn1OctetString.class)
    };

    @Override
    protected Asn1Tag[] getTags() {
        return tags;
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
