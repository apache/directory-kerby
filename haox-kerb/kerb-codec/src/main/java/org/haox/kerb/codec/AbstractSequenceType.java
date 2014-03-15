package org.haox.kerb.codec;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.haox.kerb.codec.encoding.ByteBufferASN1Object;
import org.haox.kerb.codec.encoding.HaoxASN1InputStream;
import org.haox.kerb.spec.KrbCodecMessageCode;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.KrbThrow;
import org.haox.kerb.spec.type.*;
import org.haox.kerb.spec.type.common.KrbFlags;
import org.haox.kerb.spec.type.common.KrbTime;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Enumeration;

public abstract class AbstractSequenceType extends AbstractKrbType implements SequenceType {
    public abstract KrbTag[] getTags();
    protected KrbType[] fields;

    public AbstractSequenceType() {
        KrbTag[] tags = getTags();
        this.fields = new KrbType[tags.length];
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
        ASN1EncodableVector v = new ASN1EncodableVector();
        KrbTag[] tags = getTags();
        Class<? extends KrbType> type;
        KrbType field;
        for (KrbTag tag : tags) {
            field = fields[tag.getIndex()];
            type = tag.getType();
            if (KrbInteger.class.isAssignableFrom(type)) {
                BigInteger value = ((KrbInteger) field).getValue();
                DERInteger tmp = new DERInteger(value);
                v.add(new DERTaggedObject(true, tag.getValue(), tmp));
            } else if (KrbOctetString.class.isAssignableFrom(type)) {
                byte[] value = ((KrbOctetString) field).getValue();
                DEROctetString tmp = new DEROctetString(value);
                v.add(new DERTaggedObject(true, tag.getValue(), tmp));
            }
        }
        DERSequence tmp = new DERSequence(v);
        return tmp.getEncoded();
    }

    @Override
    public void decode(byte[] content) throws KrbException {
        try {
            doDecoding(content);
        } catch (Exception e) {
            KrbThrow.out(KrbCodecMessageCode.DECODING_FAILED, e);
        }
    }

    protected void doDecoding(byte[] content) throws Exception {
        System.out.println("Start decoding for " + this.getClass().getSimpleName());
        System.out.println("The content follows:");
        HaoxASN1InputStream.asn1Dump(content, true);

        HaoxASN1InputStream stream = new HaoxASN1InputStream(content);
        ASN1Primitive asn1Obj = stream.readObject();
        if (asn1Obj == null) {
            KrbThrow.out(KrbCodecMessageCode.DECODING_FAILED);
        }
        DLSequence sequence = (DLSequence) asn1Obj;

        KrbTag[] tags = getTags();
        Enumeration<?> seqFields = sequence.getObjects();
        while(seqFields.hasMoreElements()) {
            ASN1TaggedObject tagged = null;
            tagged = DecodingUtil.as(ASN1TaggedObject.class, seqFields);

            KrbTag tag = tags[tagged.getTagNo()];
            Class<? extends KrbType> type = tag.getType();
            KrbType value = KrbFactory.create(tag.getType());
            fields[tag.getIndex()] = value;

            if (KrbInteger.class.isAssignableFrom(type)) {
                DERInteger tmp = DecodingUtil.as(DERInteger.class, tagged);
                ((KrbInteger) value).setValue(tmp.getValue());
            } else if (KrbString.class.isAssignableFrom(type)) {
                DERGeneralString tmp = DecodingUtil.as(DERGeneralString.class, tagged);
                ((KrbString) value).setValue(tmp.getString());
            } else if (KrbFlags.class.isAssignableFrom(type)) {
                DERBitString tmp = DecodingUtil.as(DERBitString.class, tagged);
                ((KrbFlags) value).setFlags(tmp.intValue());
            } else if (KrbTime.class.isAssignableFrom(type)) {
                DERInteger tmp = DecodingUtil.as(DERInteger.class, tagged);
                ((KrbTime) value).setValue(tmp.getValue().intValue());
            } else if (KrbOctetString.class.isAssignableFrom(type)) {
                DEROctetString tmp = DecodingUtil.as(DEROctetString.class, tagged);
                ((KrbOctetString) value).setValue(tmp.getOctets());
            } else if (KrbOctetString.class.isAssignableFrom(type)) {
                DEROctetString tmp = DecodingUtil.as(DEROctetString.class, tagged);
                ((KrbOctetString) value).setValue(tmp.getOctets());
            } else if (SequenceType.class.isAssignableFrom(type)) {
                ByteBufferASN1Object tmp = null;
                ASN1Object obj = tagged.getObject();
                if (obj instanceof ByteBufferASN1Object) {
                    tmp = (ByteBufferASN1Object) obj;
                }
                if (tmp != null) {
                    ((AbstractSequenceType) value).decode(tmp.toByteArray());
                }
            } else if (SequenceOfType.class.isAssignableFrom(type)) {
                ByteBufferASN1Object tmp = null;
                ASN1Object obj = tagged.getObject();
                if (obj instanceof ByteBufferASN1Object) {
                    tmp = (ByteBufferASN1Object) obj;
                }
                if (tmp != null) {
                    ((AbstractSequenceOfType) value).decode(tmp.toByteArray());
                }
            }
        }
    }

    protected <T extends KrbType> T getFieldAs(KrbTag tag, Class<T> t) throws KrbException {
        return getFieldAs(tag.getIndex(), t);
    }

    protected <T extends KrbType> T getFieldAs(int index, Class<T> t) throws KrbException {
        KrbType value = fields[index];
        if (value == null) return null;
        return (T) value;
    }

    protected void setField(KrbTag tag, KrbType value) throws KrbException {
        setField(tag.getIndex(), value);
    }

    protected void setField(int index, KrbType value) throws KrbException {
        fields[index] = value;
    }
}
