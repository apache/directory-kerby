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
        addItem(new Asn1Item(value));
    }

    public void addItem(Asn1Item item) {
        getValue().add(item);
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
            Asn1Item aValue = decodeOne(content);
            if (aValue != null) {
                addItem(aValue);
            } else {
                throw new RuntimeException("Unexpected running into here");
            }
        }
    }

    private static Asn1Item decodeOne(LimitedByteBuffer content) throws IOException {
        int tag = readTag(content);
        int tagNo = readTagNo(content, tag);
        boolean isConstructed = (tag & EncodingOption.CONSTRUCTED_FLAG) != 0;
        int length = readLength(content);
        if (length < 0) {
            throw new IOException("Unexpected length");
        }
        LimitedByteBuffer valueContent = new LimitedByteBuffer(content, length);
        content.skip(length);

        Asn1Item value = null;
        TagClass tagClass = TagClass.fromTag(tag);
        if (tagClass.isTagged()) {
            value = decodeTagged(tag, tagNo, valueContent);
        } else {
            UniversalTag tagEnum = UniversalTag.fromValue(tagNo);
            if (isConstructed) {
                value = createConsructed(tag, tagEnum, valueContent);
            } else {
                Asn1Type aValue = createPrimitive(tag, tagEnum, valueContent);
                value = new Asn1Item(aValue);
            }
        }

        return value;
    }

    private static Asn1Type createPrimitive(int tag, UniversalTag tagNo, LimitedByteBuffer content) throws IOException {
        Asn1Type result = Asn1Factory.create(tagNo);
        ((AbstractAsn1Type)result).decode(tag, tagNo.getValue(), content);
        return result;
    }

    private static Asn1Item createConsructed(int tag, UniversalTag tagNo, LimitedByteBuffer content) {
        return new Asn1Item(tag, tagNo.getValue(), content);
    }

    private static Asn1Item decodeTagged(int tag, int tagNo, LimitedByteBuffer content) throws IOException {
        return new Asn1Item(tag, tagNo, content);
    }
}
