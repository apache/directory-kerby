package org.haox.asn1.type;

import java.io.IOException;
import java.nio.ByteBuffer;

public interface Asn1Type {
    public int tag();
    public int encodingLength();
    public byte[] encode();
    public void encode(ByteBuffer buffer);
    public void decode(byte[] content) throws IOException;
    public void decode(LimitedByteBuffer content) throws IOException;
}
