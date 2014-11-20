package org.haox.kerb.spec.type.pa.token;

import org.haox.asn1.type.Asn1FieldInfo;
import org.haox.asn1.type.Asn1OctetString;
import org.haox.asn1.type.Asn1Utf8String;
import org.haox.kerb.spec.type.KerberosString;
import org.haox.kerb.spec.type.KrbSequenceType;

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
