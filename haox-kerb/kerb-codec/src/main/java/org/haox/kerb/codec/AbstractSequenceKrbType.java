package org.haox.kerb.codec;

import org.bouncycastle.asn1.*;
import org.haox.kerb.spec.KrbCodecMessageCode;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.KrbThrow;
import org.haox.kerb.spec.type.*;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.util.Enumeration;

public abstract class AbstractSequenceKrbType extends AbstractKrbType {
    protected abstract KrbTag[] getTags();
    protected KrbType[] fields;

    public AbstractSequenceKrbType() {
        KrbTag[] tags = getTags();
        fields = new KrbType[tags.length];
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
        DERObject tmp = new DERSequence(v);
        return tmp.getDEREncoded();
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
        ASN1InputStream stream = new ASN1InputStream(new ByteArrayInputStream(content));
        DERSequence sequence = null;
        sequence = DecodingUtil.as(DERSequence.class, stream);
        stream.close();

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
            } else if (KrbOctetString.class.isAssignableFrom(type)) {
                DEROctetString tmp = DecodingUtil.as(DEROctetString.class, tagged);
                ((KrbOctetString) value).setValue(tmp.getOctets());
            }
        }
    }

    protected <T extends KrbType> T getFieldAs(KrbTag tag, Class<T> t) {
        KrbType value = fields[tag.getIndex()];
        if (value == null) return null;
        return (T) value;
    }

    protected void setField(KrbTag tag, KrbType value) {
        fields[tag.getIndex()] = value;
    }

    @Override
    public boolean isSimple() {
        return false;
    }

}
