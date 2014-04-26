package org.haox.kerb.spec.type;

import org.haox.asn1.Asn1Option;
import org.haox.asn1.TagClass;

import java.nio.ByteBuffer;

/**
 * This is for application specific sequence tagged with a number.
 * ZKTODO: we need to re-write every methods in the public API to make consistent
 */
public abstract class KrbAppSequenceType extends KrbSequenceType {
    private int tagNo;

    public KrbAppSequenceType(int tagNo) {
        super();
        this.tagNo = tagNo;
    }

    @Override
    public void encode(ByteBuffer buffer, Asn1Option option) {
        int tag = TagClass.APPLICATION.getValue() | CONSTRUCTED_FLAG | tagNo;
        buffer.put((byte) tag);
        buffer.put((byte) encodingLength(option));
        super.encode(buffer, option);
    }
}
