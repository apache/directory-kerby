package org.haox.kerb.spec.type.common;

import org.haox.asn1.type.Asn1FieldInfo;
import org.haox.asn1.type.Asn1Integer;
import org.haox.asn1.type.Asn1OctetString;
import org.haox.kerb.spec.type.KrbSequenceType;

/**
 AuthorizationData       ::= SEQUENCE OF SEQUENCE {
 ad-type         [0] Int32,
 ad-data         [1] OCTET STRING
 }
 */
public class AuthorizationDataEntry extends KrbSequenceType {
    private static int AD_TYPE = 0;
    private static int AD_DATA = 1;

    static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[] {
            new Asn1FieldInfo(AD_TYPE, 0, Asn1Integer.class),
            new Asn1FieldInfo(AD_DATA, 1, Asn1OctetString.class)
    };

    public AuthorizationDataEntry() {
        super(fieldInfos);
    }

    public AuthorizationType getAuthzType() {
        Integer value = getFieldAsInteger(AD_TYPE);
        return AuthorizationType.fromValue(value);
    }

    public void setAuthzType(AuthorizationType authzType) {
        setFieldAsInt(AD_TYPE, authzType.getValue());
    }

    public byte[] getAuthzData() {
        return getFieldAsOctetBytes(AD_DATA);
    }

    public void setAuthzData(byte[] authzData) {
        setFieldAsOctetBytes(AD_DATA, authzData);
    }
}
