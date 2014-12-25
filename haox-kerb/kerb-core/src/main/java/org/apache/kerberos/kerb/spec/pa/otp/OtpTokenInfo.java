package org.apache.kerberos.kerb.spec.pa.otp;

import org.apache.haox.asn1.type.Asn1FieldInfo;
import org.apache.haox.asn1.type.Asn1Integer;
import org.apache.haox.asn1.type.Asn1OctetString;
import org.apache.haox.asn1.type.Asn1Utf8String;
import org.apache.kerberos.kerb.spec.KerberosString;
import org.apache.kerberos.kerb.spec.KrbSequenceType;
import org.apache.kerberos.kerb.spec.pa.pkinit.AlgorithmIdentifiers;

/**
 OTP-TOKENINFO ::= SEQUENCE {
     flags            [0] OTPFlags,
     otp-vendor       [1] UTF8String               OPTIONAL,
     otp-challenge    [2] OCTET STRING (SIZE(1..MAX)) OPTIONAL,
     otp-length       [3] Int32                    OPTIONAL,
     otp-format       [4] OTPFormat                OPTIONAL,
     otp-tokenID      [5] OCTET STRING             OPTIONAL,
     otp-algID        [6] AnyURI                   OPTIONAL,
     supportedHashAlg [7] SEQUENCE OF AlgorithmIdentifier OPTIONAL,
     iterationCount   [8] Int32                    OPTIONAL
 }
 */
public class OtpTokenInfo extends KrbSequenceType {
    private static int FLAGS = 0;
    private static int OTP_VENDOR = 1;
    private static int OTP_CHALLENGE = 2;
    private static int OTP_LENGTH = 3;
    private static int OTP_FORMAT = 4;
    private static int OTP_TOKEN_ID = 5;
    private static int OTP_ALG_ID = 6;
    private static int SUPPORTED_HASH_ALG = 7;
    private static int ITERATION_COUNT = 8;

    static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[] {
            new Asn1FieldInfo(FLAGS, Asn1OctetString.class, true),
            new Asn1FieldInfo(OTP_VENDOR, Asn1Utf8String.class),
            new Asn1FieldInfo(OTP_CHALLENGE, Asn1OctetString.class, true),
            new Asn1FieldInfo(OTP_LENGTH, KerberosString.class),
            new Asn1FieldInfo(OTP_FORMAT, Asn1OctetString.class, true),
            new Asn1FieldInfo(OTP_TOKEN_ID, Asn1Utf8String.class),
            new Asn1FieldInfo(OTP_ALG_ID, Asn1OctetString.class, true),
            new Asn1FieldInfo(SUPPORTED_HASH_ALG, AlgorithmIdentifiers.class),
            new Asn1FieldInfo(ITERATION_COUNT, Asn1Integer.class, true)
    };

    public OtpTokenInfo() {
        super(fieldInfos);
    }
}
