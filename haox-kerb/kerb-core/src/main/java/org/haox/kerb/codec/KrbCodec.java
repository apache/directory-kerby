package org.haox.kerb.codec;

import org.haox.kerb.spec.KrbCodecMessageCode;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.KrbThrow;
import org.haox.kerb.spec.type.KrbFactory;
import org.haox.kerb.spec.type.KrbType;

public class KrbCodec {
    public static byte[] encode(KrbType krbObj) throws KrbException {
        if (! (krbObj instanceof KrbEncodable)) {
            KrbThrow.out(KrbCodecMessageCode.NOT_ENCODABLE);
        }

        KrbEncodable encodable = (KrbEncodable) krbObj;
        return encodable.encode();
    }

    public static <T extends KrbType> T decode(byte[] content, Class<T> krbType) throws KrbException {
        KrbType implObj = KrbFactory.create(krbType);
        if (! (implObj instanceof KrbEncodable)) {
            KrbThrow.out(KrbCodecMessageCode.NOT_ENCODABLE);
        }

        KrbEncodable encodable = (KrbEncodable) implObj;
        encodable.decode(content);
        return (T) implObj;
    }
}
