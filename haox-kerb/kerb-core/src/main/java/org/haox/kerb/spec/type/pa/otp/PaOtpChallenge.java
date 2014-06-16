package org.haox.kerb.spec.type.pa.otp;

import org.haox.asn1.type.Asn1FieldInfo;
import org.haox.asn1.type.Asn1OctetString;
import org.haox.asn1.type.Asn1Utf8String;
import org.haox.kerb.spec.type.KerberosString;
import org.haox.kerb.spec.type.KrbSequenceType;

/**
 PA-OTP-CHALLENGE ::= SEQUENCE {
     nonce            [0] OCTET STRING,
     otp-service      [1] UTF8String               OPTIONAL,
     otp-tokenInfo    [2] SEQUENCE (SIZE(1..MAX)) OF OTP-TOKENINFO,
     salt             [3] KerberosString           OPTIONAL,
     s2kparams        [4] OCTET STRING             OPTIONAL,
 }
 */
public class PaOtpChallenge extends KrbSequenceType {
    private static int NONCE = 0;
    private static int OTP_SERVICE = 1;
    private static int OTP_TOKEN_INFO = 2;
    private static int SALT = 3;
    private static int S2KPARAMS = 4;

    static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[] {
            new Asn1FieldInfo(NONCE, Asn1OctetString.class, true),
            new Asn1FieldInfo(OTP_SERVICE, Asn1Utf8String.class),
            new Asn1FieldInfo(OTP_TOKEN_INFO, Asn1OctetString.class, true),
            new Asn1FieldInfo(SALT, KerberosString.class),
            new Asn1FieldInfo(S2KPARAMS, Asn1OctetString.class, true)
    };

    public PaOtpChallenge() {
        super(fieldInfos);
    }
}
