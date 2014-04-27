package org.haox.asn1.type;

import org.haox.asn1.EncodingOption;
import org.haox.asn1.TaggingOption;

import java.io.IOException;
import java.nio.ByteBuffer;

public interface Asn1Type {
    public int tagClass();
    public int tagNo();
    public byte[] encode(EncodingOption encodingOption);
    public void encode(ByteBuffer buffer, EncodingOption encodingOption);
    public void taggedEncode(ByteBuffer buffer, TaggingOption taggingOption, EncodingOption encodingOption);
    public byte[] encode();
    public void encode(ByteBuffer buffer);
    public void decode(byte[] content) throws IOException;
    public void decode(ByteBuffer content) throws IOException;
    public void taggedDecode(ByteBuffer content, TaggingOption taggingOption) throws IOException;
}
