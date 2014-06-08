package org.haox.kerb.codec.spnego;

import org.bouncycastle.asn1.*;
import org.haox.kerb.codec.DecodingUtil;
import org.haox.kerb.codec.util.HaoxASN1InputStream;
import org.haox.kerb.codec.util.HaoxDERApplicationSpecific;

import java.io.IOException;
import java.util.Enumeration;

public class SpnegoInitToken extends SpnegoToken {

    public static final int DELEGATION = 0x40;
    public static final int MUTUAL_AUTHENTICATION = 0x20;
    public static final int REPLAY_DETECTION = 0x10;
    public static final int SEQUENCE_CHECKING = 0x08;
    public static final int ANONYMITY = 0x04;
    public static final int CONFIDENTIALITY = 0x02;
    public static final int INTEGRITY = 0x01;

    private String[] mechanisms;
    private int contextFlags;

    public SpnegoInitToken(byte[] token) throws IOException {
        HaoxASN1InputStream stream = new HaoxASN1InputStream(token);
        HaoxDERApplicationSpecific constructed = DecodingUtil.as(HaoxDERApplicationSpecific.class,
                stream);
        if(constructed == null || !constructed.isConstructed())
            throw new IOException("spnego.token.malformed");

        stream = new HaoxASN1InputStream(constructed.getByteBuffer(), constructed.getLimit());
        DERObjectIdentifier spnegoOid = DecodingUtil.as(DERObjectIdentifier.class, stream);
        if(!spnegoOid.getId().equals(SpnegoConstants.SPNEGO_OID))
            throw new IOException("spnego.token.invalid");

        ASN1TaggedObject tagged = DecodingUtil.as(ASN1TaggedObject.class, stream);
        ASN1Sequence sequence = ASN1Sequence.getInstance(tagged, true);
        Enumeration<?> fields = sequence.getObjects();
        while(fields.hasMoreElements()) {
            tagged = DecodingUtil.as(ASN1TaggedObject.class, fields);
            switch (tagged.getTagNo()) {
            case 0:
                sequence = ASN1Sequence.getInstance(tagged, true);
                mechanisms = new String[sequence.size()];
                for(int i = mechanisms.length - 1; i >= 0; i--) {
                    DERObjectIdentifier mechanismOid = DecodingUtil.as(
                            DERObjectIdentifier.class, sequence.getObjectAt(i));
                    mechanisms[i] = mechanismOid.getId();
                }
                if(sequence.size() > 0)
                    mechanism = mechanisms[0];
                break;
            case 1:
                DERBitString derFlags = DERBitString.getInstance(tagged, true);
                contextFlags = derFlags.getBytes()[0] & 0xff;
                break;
            case 2:
                ASN1OctetString mechanismTokenString = ASN1OctetString
                        .getInstance(tagged, true);
                mechanismToken = mechanismTokenString.getOctets();
                break;
            case 3:
                ASN1OctetString mechanismListString = ASN1OctetString.getInstance(tagged, true);
                mechanismList = mechanismListString.getOctets();
                break;
            default:
                Object[] args = new Object[]{tagged.getTagNo()};
                throw new IOException("spnego.field.invalid");
            }
        }
    }

    public int getContextFlags() {
        return contextFlags;
    }

    public boolean getContextFlag(int flag) {
        return (getContextFlags() & flag) == flag;
    }

    public String[] getMechanisms() {
        return mechanisms;
    }

}
