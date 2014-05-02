package org.haox.asn1.type;

import org.haox.asn1.*;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

public class Asn1Collection extends AbstractAsn1Type<List<Asn1Item>>
{
    public Asn1Collection(TagClass tagClass, int tagNo) {
        super(tagClass, tagNo);
        setValue(new ArrayList<Asn1Item>());
        setEncodingOption(EncodingOption.CONSTRUCTED);
    }

    @Override
    protected boolean isConstructed() {
        return true;
    }

    public void addItem(Asn1Type value) {
        if (value instanceof Asn1Item) {
            getValue().add((Asn1Item) value);
        } else {
            getValue().add(new Asn1Item(value));
        }
    }

    public void clear() {
        getValue().clear();
    }

    @Override
    protected int encodingBodyLength() {
        List<Asn1Item> valueItems = getValue();
        int allLen = 0;
        for (Asn1Item item : valueItems) {
            if (item != null) {
                allLen += ((AbstractAsn1Type) item.getValue()).encodingLength();
            }
        }
        return allLen;
    }

    @Override
    protected void encodeBody(ByteBuffer buffer) {
        List<Asn1Item> valueItems = getValue();
        for (Asn1Item item : valueItems) {
            if (item != null) {
                item.getValue().encode(buffer);
            }
        }
    }

    @Override
    protected void decodeBody(LimitedByteBuffer content) throws IOException {
        while (content.available()) {
            Asn1Type aValue = decodeOne(content);
            if (aValue != null) {
                if (aValue instanceof Asn1Item) {
                    addItem((Asn1Item) aValue);
                } else {
                    addItem(aValue);
                }
            } else {
                throw new RuntimeException("Unexpected running into here");
            }
        }
    }
}
