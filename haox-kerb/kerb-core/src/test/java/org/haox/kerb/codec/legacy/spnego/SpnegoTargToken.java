package org.haox.kerb.codec.legacy.spnego;

import org.bouncycastle.asn1.*;
import org.haox.kerb.codec.legacy.DecodingException;
import org.haox.kerb.codec.legacy.DecodingUtil;
import org.haox.kerb.codec.encoding.HaoxASN1InputStream;

import java.io.IOException;
import java.util.Enumeration;

public class SpnegoTargToken extends SpnegoToken {

    public static final int UNSPECIFIED_RESULT = -1;
    public static final int ACCEPT_COMPLETED = 0;
    public static final int ACCEPT_INCOMPLETE = 1;
    public static final int REJECTED = 2;

    private int result = UNSPECIFIED_RESULT;

    public SpnegoTargToken(byte[] token) throws DecodingException {
        HaoxASN1InputStream stream = new HaoxASN1InputStream(token);
        ASN1TaggedObject tagged;
        tagged = DecodingUtil.as(ASN1TaggedObject.class, stream);

        ASN1Sequence sequence = ASN1Sequence.getInstance(tagged, true);
        Enumeration<?> fields = sequence.getObjects();
        while(fields.hasMoreElements()) {
            tagged = DecodingUtil.as(ASN1TaggedObject.class, fields);
            switch (tagged.getTagNo()) {
            case 0:
                DEREnumerated enumerated = DEREnumerated.getInstance(tagged, true);
                result = enumerated.getValue().intValue();
                break;
            case 1:
                DERObjectIdentifier mechanismOid = DERObjectIdentifier.getInstance(tagged, true);
                mechanism = mechanismOid.getId();
                break;
            case 2:
                ASN1OctetString mechanismTokenString = ASN1OctetString.getInstance(tagged, true);
                mechanismToken = mechanismTokenString.getOctets();
                break;
            case 3:
                ASN1OctetString mechanismListString = ASN1OctetString.getInstance(tagged, true);
                mechanismList = mechanismListString.getOctets();
                break;
            default:
                Object[] args = new Object[]{tagged.getTagNo()};
                throw new DecodingException("spnego.field.invalid", args, null);
            }
        }
    }

    public int getResult() {
        return result;
    }

}
