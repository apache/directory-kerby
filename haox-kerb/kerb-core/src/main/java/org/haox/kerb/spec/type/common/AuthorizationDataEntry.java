package org.haox.kerb.spec.type.common;

import org.haox.asn1.type.AbstractSequenceType;
import org.haox.asn1.type.Asn1Integer;
import org.haox.asn1.type.Asn1OctetString;
import org.haox.asn1.Asn1Tag;
import org.haox.kerb.spec.KrbException;

/**
 AuthorizationData       ::= SEQUENCE OF SEQUENCE {
 ad-type         [0] Int32,
 ad-data         [1] OCTET STRING
 }
 */
public class AuthorizationDataEntry extends AbstractSequenceType {
    private static int AD_TYPE = 0;
    private static int AD_DATA = 1;

    static Asn1Tag[] tags = new Asn1Tag[] {
            new Asn1Tag(AD_TYPE, 0, Asn1Integer.class),
            new Asn1Tag(AD_DATA, 1, Asn1OctetString.class)
    };

    @Override
    protected Asn1Tag[] getTags() {
        return tags;
    }

    public AuthorizationType getAuthzType() throws KrbException {
        Integer value = getFieldAsInteger(AD_TYPE);
        return AuthorizationType.fromValue(value);
    }

    public void setAuthzType(AuthorizationType authzType) throws KrbException {
        setFieldAsInt(AD_TYPE, authzType.getValue());
    }

    public byte[] getAuthzData() throws KrbException {
        return getFieldAsOctetBytes(AD_DATA);
    }

    public void setAuthzData(byte[] authzData) throws KrbException {
        setFieldAsOctetBytes(AD_DATA, authzData);
    }
}
