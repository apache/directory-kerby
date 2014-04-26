package org.haox.asn1.type;

import org.haox.asn1.Asn1Option;
import org.haox.asn1.LimitedByteBuffer;

import java.io.IOException;
import java.nio.ByteBuffer;

public interface Asn1Type {
    public int tagClass();
    public int tagNo();
    public byte[] encode(Asn1Option option);
    public void encode(ByteBuffer buffer, Asn1Option option);
    public byte[] encode();
    public void encode(ByteBuffer buffer);
    public void decode(byte[] content) throws IOException;
    public void decode(LimitedByteBuffer content) throws IOException;
    public void decode(int tag, int tagNo, LimitedByteBuffer content) throws IOException;
}
