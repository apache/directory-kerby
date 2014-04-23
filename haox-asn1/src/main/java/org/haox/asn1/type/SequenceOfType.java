package org.haox.asn1.type;

import org.haox.asn1.Asn1Option;
import org.haox.asn1.LimitedByteBuffer;

import java.io.IOException;
import java.lang.reflect.ParameterizedType;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

public class SequenceOfType<T extends Asn1Type>
        extends AbstractAsn1Type<SequenceOfType<T>> {
    private List<T> elements;

    public SequenceOfType() {
        this(-1);
    }

    public SequenceOfType(int tag) {
        super(tag);
        setValue(this);
        elements = new ArrayList<T>();
    }

    @Override
    protected int bodyLength() {
        int allLen = 0;
        for (Asn1Type field : elements) {
            if (field != null) {
                allLen += field.encodingLength();
            }
        }
        return allLen;
    }

    @Override
    public void encode(ByteBuffer buffer, Asn1Option option) {
        buffer.put((byte) tag());
        buffer.put((byte) bodyLength());
        encodeBody(buffer);
    }

    private void encodeBody(ByteBuffer buffer) {
        Asn1Sequence sequence = new Asn1Sequence();
        for (Asn1Type field: elements) {
            if (field != null) {
                sequence.addField(field);
            }
        }
        sequence.encode(buffer);
    }

    @Override
    protected void decodeValue(LimitedByteBuffer content) throws IOException {
        Asn1Sequence sequence = new Asn1Sequence();
        sequence.decode(content);

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
