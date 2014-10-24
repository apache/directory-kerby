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
        int nElements = items != null ? items.size() : 0;
        List<T> results = new ArrayList<T>(nElements);
        if (nElements > 0) {
            for (Asn1Item item : items) {
                if (!item.isFullyDecoded()) {
                    try {
                        item.decodeValueAs(getElementType());
                    } catch (IOException e) {
                        throw new RuntimeException(e);
                    }
                }
                results.add((T) item.getValue());
            }
        }
        return results;
    }

    public void setElements(List<T> elements) {
        super.clear();

        for (T ele : elements) {
            addElement(ele);
        }
    }

    public void addElements(T ... elements) {
        for (T ele : elements) {
            addElement(ele);
        }
    }

    public void addElement(T element) {
        super.addItem(element);
    }

    @Override
    public void addItem(Asn1Type value) {
        Class<T> eleType = getElementType();
        if (value instanceof Asn1Item) {
            super.addItem(value);
        } else if (! eleType.isInstance(value)) {
            throw new RuntimeException("Unexpected element type " + value.getClass().getCanonicalName());
        } else {
            addElement((T) value);
        }
    }

    protected Class<T> getElementType() {
        Class<T> elementType = (Class<T>) ((ParameterizedType) getClass().getGenericSuperclass()).getActualTypeArguments()[0];
        return elementType;
    }
}
