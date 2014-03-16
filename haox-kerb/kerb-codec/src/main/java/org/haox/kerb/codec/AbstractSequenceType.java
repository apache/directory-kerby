package org.haox.kerb.codec;

import org.bouncycastle.asn1.*;
import org.haox.kerb.codec.encoding.ByteBufferASN1Object;
import org.haox.kerb.codec.encoding.HaoxASN1InputStream;
import org.haox.kerb.codec.encoding.HaoxDERApplicationSpecific;
import org.haox.kerb.spec.KrbCodecMessageCode;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.KrbThrow;
import org.haox.kerb.spec.type.*;

import java.math.BigInteger;
import java.util.Enumeration;

public abstract class AbstractSequenceType extends AbstractSequenceBase implements SequenceType {
    public abstract KrbTag[] getTags();
    protected KrbType[] fields;

    public AbstractSequenceType() {
        KrbTag[] tags = getTags();
        this.fields = new KrbType[tags.length];
    }

    @Override
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
    protected void doDecoding(byte[] content) throws Exception {
        HaoxASN1InputStream stream = new HaoxASN1InputStream(content);
        ASN1Primitive asn1Obj = stream.readObject();
        if (asn1Obj == null) {
            KrbThrow.out(KrbCodecMessageCode.DECODING_FAILED);
        }
        if (asn1Obj instanceof ByteBufferASN1Object) {
            ByteBufferASN1Object tmp = null;
            if (asn1Obj instanceof ByteBufferASN1Object) {
                tmp = (ByteBufferASN1Object) asn1Obj;
            }
            if (tmp != null) {
                doDecoding(tmp.toByteArray());
                return;
            } else {
                KrbThrow.out(KrbCodecMessageCode.DECODING_FAILED);
            }
        }
        DLSequence sequence = (DLSequence) asn1Obj;

        KrbTag[] tags = getTags();
        Enumeration<?> seqFields = sequence.getObjects();
        ASN1TaggedObject tagged = null;
        while(seqFields.hasMoreElements()) {
            tagged = (ASN1TaggedObject) seqFields.nextElement();

            KrbTag tag = tags[tagged.getTagNo()];
            Class<? extends KrbType> type = tag.getType();
            KrbType value = convertAsn1ObjectAs(type, tagged.getObject());
            fields[tag.getIndex()] = value;
        }
    }

    protected <T extends KrbType> T getFieldAs(KrbTag tag, Class<T> t) throws KrbException {
        return getFieldAs(tag.getIndex(), t);
    }

    protected String getFieldAsString(KrbTag tag) throws KrbException {
        KrbType value = fields[tag.getIndex()];
        if (value == null) return null;

        if (value instanceof KrbString) {
            return ((KrbString) value).getValue();
        }

        return null;
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
