package org.apache.kerberos.kerb.spec.pa.token;

import org.apache.haox.asn1.type.Asn1FieldInfo;
import org.apache.kerberos.kerb.spec.KrbSequenceType;

/**
 PA-TOKEN-CHALLENGE ::= SEQUENCE {
    tokenInfos       [0] SEQUENCE (SIZE(1..MAX)) OF TokenInfo,
 }
*/
public class PaTokenChallenge extends KrbSequenceType {
    private static int TOKENINFOS = 0;

    static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[] {
            new Asn1FieldInfo(TOKENINFOS, TokenInfos.class)
    };

    public PaTokenChallenge() {
        super(fieldInfos);
    }
}
