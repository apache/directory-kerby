package org.haox.asn1.type;

import org.haox.asn1.EncodingOption;
import org.haox.asn1.LimitedByteBuffer;
import org.haox.asn1.TagClass;
import org.haox.asn1.UniversalTag;

import java.io.IOException;
import java.lang.reflect.ParameterizedType;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

public class SequenceOfType<T extends Asn1Type> extends AbstractAsn1Type<SequenceOfType<T>> {
    private List<T> elements;

    public SequenceOfType() {
        super(TagClass.UNIVERSAL, UniversalTag.SEQUENCE.getValue());
        this.elements = new ArrayList<T>();
        setEncodingOption(EncodingOption.CONSTRUCTED);
    }

    @Override
    protected boolean isConstructed() {
        return true;
    }

    @Override
    protected int encodingBodyLength() {
        int allLen = 0;
        for (Asn1Type field : elements) {
            if (field != null) {
                allLen += ((AbstractAsn1Type) field).encodingLength();
            }
        }
        return allLen;
    }

    @Override
    protected void encodeBody(ByteBuffer buffer) {
        for (Asn1Type field : elements) {
            if (field != null) {
                field.encode(buffer);
            }
        }
    }

    @Override
    protected void decodeBody(LimitedByteBuffer content) throws IOException {
        Asn1Sequence sequence = new Asn1Sequence();
        sequence.decode(tag(), tagNo(), content);

        elements.clear();
        for (Asn1SequenceField field : sequence.getFields()) {
            //http://stackoverflow.com/questions/1901164/get-type-of-a-generic-parameter-in-java-with-reflection
            Class<T> type = (Class<T>) ((ParameterizedType) getClass().getGenericSuperclass()).getActualTypeArguments()[0];
            field.decodeAs(type);
            add((T) field.getFieldValue());
        }
    }

    public void clear() {
        elements.clear();
    }

    public void setElements(List<T> elements) {
        this.elements.clear();
        this.elements.addAll(elements);
    }

    public List<T> getElements() {
        return elements;
    }

    public void add(T element) {
        elements.add(element);
    }

    public List<String> getAsStrings() {
        List<String> results = new ArrayList<String>();
        for (T ele : elements) {
            if (ele instanceof Asn1String) {
                results.add(((Asn1String) ele).getValue());
            }
            throw new RuntimeException("The targeted field type isn't of string");
        }
        return results;
    }
}
