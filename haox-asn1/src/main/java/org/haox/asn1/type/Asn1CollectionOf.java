package org.haox.asn1.type;

import org.haox.asn1.TagClass;

import java.io.IOException;
import java.lang.reflect.ParameterizedType;
import java.util.ArrayList;
import java.util.List;

public abstract class Asn1CollectionOf<T extends Asn1Type> extends Asn1Collection
{
    public Asn1CollectionOf(TagClass tagClass, int tagNo) {
        super(tagClass, tagNo);
    }

    public List<T> getElements() {
        List<Asn1Item> items = getValue();
        List<T> results = new ArrayList<T>(items.size());
        for (Asn1Item item : items) {
            if (item.isFullyDecoded()) {
                results.add((T) item.getValue());
            } else {
                try {
                    item.decodeValueAs(getElementType());
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            }
        }
        return results;
    }

    public void addElement(T element) {
        addItem(new Asn1Item(element));
    }

    @Override
    public void addItem(Asn1Type value) {
        if (! getElementType().isInstance(value)) {
            throw new RuntimeException("Unexpected element type " + value.getClass().getCanonicalName());
        }
        addElement((T) value);
    }

    protected Class<T> getElementType() {
        Class<T> elementType = (Class<T>) ((ParameterizedType) getClass().getGenericSuperclass()).getActualTypeArguments()[0];
        return elementType;
    }
}
