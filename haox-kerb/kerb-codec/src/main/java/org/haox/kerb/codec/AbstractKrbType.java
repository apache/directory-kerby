package org.haox.kerb.codec;

import org.haox.kerb.codec.encoding.HaoxASN1InputStream;
import org.haox.kerb.spec.KrbCodecMessageCode;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.KrbThrow;
import org.haox.kerb.spec.type.KrbType;

import java.io.IOException;

public abstract class AbstractKrbType implements KrbType, KrbEncodable {
    @Override
    public void decode(byte[] content)  throws KrbException {
        System.out.println("Start decoding for " + this.getClass().getSimpleName());
        System.out.println("The content follows:");
        try {
            HaoxASN1InputStream.asn1Dump(content, true);
        } catch (IOException e) {
            KrbThrow.out(KrbCodecMessageCode.DECODING_FAILED, e);
        }

        try {
            doDecoding(content);
        } catch (Exception e) {
            KrbThrow.out(KrbCodecMessageCode.DECODING_FAILED, e);
        }
    }

    @Override
    public byte[] encode() throws KrbException {
        try {
            return doEncoding();
        } catch (Exception e) {
            KrbThrow.out(KrbCodecMessageCode.DECODING_FAILED, e);
        }
        return null;
    }

    protected byte[] doEncoding() throws Exception {
        return null;
    }

    protected void doDecoding(byte[] content) throws Exception {
    }
}
