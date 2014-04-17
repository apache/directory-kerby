package org.haox.kerb.codec;

import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DLSequence;
import org.haox.kerb.codec.encoding.HaoxASN1InputStream;
import org.haox.kerb.spec.KrbCodecMessageCode;
import org.haox.kerb.spec.KrbThrow;
import org.haox.kerb.spec.type.KrbType;
import org.haox.kerb.spec.type.SequenceOfType;

import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

public abstract class AbstractSequenceOfType extends AbstractSequenceBase implements SequenceOfType {
    protected List<KrbType> elements;
    public abstract Class<? extends KrbType> getElementType();

    public AbstractSequenceOfType() {
        this.elements = new ArrayList<KrbType>();
    }

    protected void doDecoding(byte[] content) throws Exception {
        HaoxASN1InputStream stream = new HaoxASN1InputStream(content);
        ASN1Primitive asn1Obj = stream.readObject();
        if (asn1Obj == null) {
            KrbThrow.out(KrbCodecMessageCode.DECODING_FAILED);
        }
        DLSequence sequence = (DLSequence) asn1Obj;

        Enumeration<?> seqFields = sequence.getObjects();
        ASN1Primitive asn1Ele = null;
        while(seqFields.hasMoreElements()) {
            asn1Ele = (ASN1Primitive) seqFields.nextElement();

            Class<? extends KrbType> type = getElementType();
            KrbType value = convertAsn1ObjectAs(type, asn1Ele);
            this.elements.add(value);
        }
    }

    protected <T extends KrbType> List<T> getElementsAs(Class<T> t) {
        return (List<T>) elements;
    }
}
