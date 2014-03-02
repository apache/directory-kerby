package org.haox.kerb.codec;

import org.haox.kerb.spec.KrbCodecMessageCode;
import org.haox.kerb.spec.KrbException;
import org.haox.kerb.spec.KrbThrow;
import org.haox.kerb.spec.type.KrbType;
import org.haox.kerb.spec.type.SequenceOfType;

import java.util.ArrayList;
import java.util.List;

public abstract class AbstractSequenceOfType extends AbstractKrbType implements SequenceOfType {
    protected List<KrbType> elements;
    protected Class<? extends KrbType> elementType;

    public AbstractSequenceOfType(Class<? extends KrbType> elementType) {
        this.elementType = elementType;
        this.elements = new ArrayList<KrbType>();
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

    @Override
    public void decode(byte[] content) throws KrbException {
        try {
            doDecoding(content);
        } catch (Exception e) {
            KrbThrow.out(KrbCodecMessageCode.DECODING_FAILED, e);
        }
    }

    protected void doDecoding(byte[] content) throws Exception {
    }

    protected <T extends KrbType> List<T> getElementsAs(Class<T> t) {
        return (List<T>) elements;
    }

    protected void addElement(KrbType element) {
        this.elements.add(element);
    }

    @Override
    public Class<? extends KrbType> getElementType() {
        return elementType;
    }
}
