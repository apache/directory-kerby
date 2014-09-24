package org.haox.asn1;

import org.haox.asn1.type.AbstractAsn1Type;
import org.haox.asn1.type.Asn1Type;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

/**
 * Asn1 encoder
 */
public class Asn1OutputBuffer {
    private List<Asn1Type> objects;

    public Asn1OutputBuffer() {
        this.objects = new ArrayList<Asn1Type>(3);
    }

    public void write(Asn1Type value) {
        objects.add(value);
    }

    public void write(Asn1Type value, EncodingOption option) {
        value.setEncodingOption(option);
        objects.add(value);
    }

    public ByteBuffer getOutput() {
        int len = encodingLength();
        ByteBuffer byteBuffer = ByteBuffer.allocate(len);
        encode(byteBuffer);
        return byteBuffer;
    }

    private int encodingLength() {
        int allLen = 0;
        for (Asn1Type item : objects) {
            if (item != null) {
                allLen += ((AbstractAsn1Type) item).encodingLength();
            }
        }
        return allLen;
    }

    private void encode(ByteBuffer buffer) {
        for (Asn1Type item : objects) {
            if (item != null) {
                item.encode(buffer);
            }
        }
    }
}
