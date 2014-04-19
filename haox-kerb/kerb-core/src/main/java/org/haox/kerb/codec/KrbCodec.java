package org.haox.kerb.codec;

import org.haox.asn1.type.Asn1Type;
import org.haox.kerb.spec.KrbCodecMessageCode;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.KrbThrow;

import java.io.IOException;

public class KrbCodec {
    public static byte[] encode(Asn1Type krbObj) throws KrbException {
        return krbObj.encode();
    }

    public static <T extends Asn1Type> T decode(byte[] content, Class<T> krbType) throws KrbException {
        Asn1Type implObj = null;
        try {
            implObj = krbType.newInstance();
        } catch (Exception e) {
            KrbThrow.out(KrbCodecMessageCode.DECODING_FAILED, e);
        }

        try {
            implObj.decode(content);
        } catch (IOException e) {
            KrbThrow.out(KrbCodecMessageCode.DECODING_FAILED, e);
        }

        return (T) implObj;
    }
}
