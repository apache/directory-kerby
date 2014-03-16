package org.haox.kerb.codec;

import org.bouncycastle.asn1.*;
import org.haox.kerb.codec.encoding.ByteBufferASN1Object;
import org.haox.kerb.spec.KrbCodecMessageCode;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.KrbThrow;
import org.haox.kerb.spec.type.*;
import org.haox.kerb.spec.type.common.KrbFlags;
import org.haox.kerb.spec.type.common.KrbTime;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.util.Enumeration;

public abstract class AbstractSequenceBase extends AbstractKrbType {

    protected KrbType convertAsn1ObjectAs(Class<? extends KrbType> type, ASN1Primitive asn1Obj) throws Exception {
        KrbType value = KrbFactory.create(type);

        if (KrbInteger.class.isAssignableFrom(type)) {
            DERInteger tmp = DecodingUtil.as(DERInteger.class, asn1Obj);
            ((KrbInteger) value).setValue(tmp.getValue());
        } else if (KrbString.class.isAssignableFrom(type)) {
            DERGeneralString tmp = DecodingUtil.as(DERGeneralString.class, asn1Obj);
            ((KrbString) value).setValue(tmp.getString());
        } else if (KrbFlags.class.isAssignableFrom(type)) {
            DERBitString tmp = DecodingUtil.as(DERBitString.class, asn1Obj);
            ((KrbFlags) value).setFlags(tmp.intValue());
        } else if (KrbTime.class.isAssignableFrom(type)) {
            ASN1GeneralizedTime tmp = DecodingUtil.as(ASN1GeneralizedTime.class, asn1Obj);
            ((KrbTime) value).setValue(tmp.getDate().getTime());
        } else if (KrbOctetString.class.isAssignableFrom(type)) {
            DEROctetString tmp = DecodingUtil.as(DEROctetString.class, asn1Obj);
            ((KrbOctetString) value).setValue(tmp.getOctets());
        } else if (KrbOctetString.class.isAssignableFrom(type)) {
            DEROctetString tmp = DecodingUtil.as(DEROctetString.class, asn1Obj);
            ((KrbOctetString) value).setValue(tmp.getOctets());
        } else if (SequenceType.class.isAssignableFrom(type)) {
            ByteBufferASN1Object tmp = null;
            if (asn1Obj instanceof ByteBufferASN1Object) {
                tmp = (ByteBufferASN1Object) asn1Obj;
            }
            if (tmp != null) {
                ((AbstractSequenceType) value).decode(tmp.toByteArray());
            }
        } else if (SequenceOfType.class.isAssignableFrom(type)) {
            ByteBufferASN1Object tmp = null;
            if (asn1Obj instanceof ByteBufferASN1Object) {
                tmp = (ByteBufferASN1Object) asn1Obj;
            }
            if (tmp != null) {
                ((AbstractSequenceOfType) value).decode(tmp.toByteArray());
            }
        }

        return value;
    }
}
