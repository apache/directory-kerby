package org.haox.kerb.spec.type.common;

import org.haox.asn1.type.Asn1Integer;
import org.haox.asn1.type.Asn1OctetString;
import org.haox.asn1.type.Asn1Tag;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.type.KrbSequenceType;

/**
 TransitedEncoding       ::= SEQUENCE {
 tr-type         [0] Int32 -- must be registered --,
 contents        [1] OCTET STRING
 }
 */
public class TransitedEncoding extends KrbSequenceType {
    private static int TR_TYPE = 0;
    private static int CONTENTS = 1;

    static Asn1Tag[] tags = new Asn1Tag[] {
            new Asn1Tag(TR_TYPE, 1, Asn1Integer.class),
            new Asn1Tag(CONTENTS, 2, Asn1OctetString.class)
    };

    @Override
    protected Asn1Tag[] getTags() {
        return tags;
    }

    public TransitedEncodingType getTrType() throws KrbException {
        Integer value = getFieldAsInteger(TR_TYPE);
        return TransitedEncodingType.fromValue(value);
    }

    public void setTrType(TransitedEncodingType trType) throws KrbException {
        setField(TR_TYPE, trType);
    }

    public byte[] getContents() throws KrbException {
        return getFieldAsOctetBytes(CONTENTS);
    }

    public void setContents(byte[] contents) throws KrbException {
        setFieldAsOctetBytes(CONTENTS, contents);
    }
}
