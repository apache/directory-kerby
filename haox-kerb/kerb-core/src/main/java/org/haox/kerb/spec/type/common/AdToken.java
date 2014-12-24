package org.haox.kerb.spec.type.common;

import org.haox.asn1.type.Asn1FieldInfo;
import org.haox.kerb.spec.type.KrbSequenceType;

/**
 AD-TOKEN ::= SEQUENCE {
    token     [0]  OCTET STRING,
 }
*/
public class AdToken extends KrbSequenceType {
    private static int TOKEN = 0;

    static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[] {
            new Asn1FieldInfo(TOKEN, KrbToken.class)
    };

    public AdToken() {
        super(fieldInfos);
    }

    public KrbToken getToken() {
        return getFieldAs(TOKEN, KrbToken.class);
    }

    public void setToken(KrbToken token) {
        setFieldAs(TOKEN, token);
    }

}
