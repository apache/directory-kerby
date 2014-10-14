package org.haox.kerb.codec;

import org.haox.asn1.LimitedByteBuffer;
import org.haox.asn1.type.AbstractAsn1Type;
import org.haox.asn1.type.Asn1Type;
import org.haox.kerb.spec.CodecMessageCode;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.KrbThrow;
import org.haox.kerb.spec.type.ap.ApReq;
import org.haox.kerb.spec.type.common.KrbMessage;
import org.haox.kerb.spec.type.common.KrbMessageType;
import org.haox.kerb.spec.type.kdc.AsRep;
import org.haox.kerb.spec.type.kdc.AsReq;
import org.haox.kerb.spec.type.kdc.TgsRep;
import org.haox.kerb.spec.type.kdc.TgsReq;

import java.io.IOException;
import java.nio.ByteBuffer;

public class KrbCodec {

    public static byte[] encode(Asn1Type krbObj) throws KrbException {
        return krbObj.encode();
    }

    public static <T extends Asn1Type> T decode(byte[] content, Class<T> krbType) throws KrbException {
        Asn1Type implObj = null;
        try {
            implObj = krbType.newInstance();
        } catch (Exception e) {
            KrbThrow.out(CodecMessageCode.DECODING_FAILED, e);
        }

        try {
            implObj.decode(content);
        } catch (IOException e) {
            KrbThrow.out(CodecMessageCode.DECODING_FAILED, e);
        }

        return (T) implObj;
    }

    public static KrbMessage decodeMessage(ByteBuffer byteBuffer) throws IOException {
        LimitedByteBuffer limitedBuffer = new LimitedByteBuffer(byteBuffer);
        int tag = AbstractAsn1Type.readTag(limitedBuffer);
        int tagNo = AbstractAsn1Type.readTagNo(limitedBuffer, tag);
        int length = AbstractAsn1Type.readLength(limitedBuffer);
        LimitedByteBuffer valueBuffer = new LimitedByteBuffer(limitedBuffer, length);

        KrbMessage msg = null;
        KrbMessageType msgType = KrbMessageType.fromValue(tagNo);
        if (msgType == KrbMessageType.AS_REQ) {
            msg = new AsReq();
        } else if (msgType == KrbMessageType.AS_REP) {
            msg = new AsRep();
        } else if (msgType == KrbMessageType.TGS_REQ) {
            msg = new TgsReq();
        } else if (msgType == KrbMessageType.TGS_REP) {
            msg = new TgsRep();
        } else if (msgType == KrbMessageType.AP_REQ) {
            msg = new ApReq();
        } else if (msgType == KrbMessageType.AP_REP) {
            msg = new ApReq();
        } else {
            throw new IOException("To be supported krb message type with tag: " + tag);
        }
        msg.decode(tag, tagNo, valueBuffer);

        return msg;
    }

}
