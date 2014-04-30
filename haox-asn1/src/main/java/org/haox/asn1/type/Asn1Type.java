package org.haox.asn1.type;

import org.haox.asn1.EncodingOption;
import org.haox.asn1.TagClass;
import org.haox.asn1.TaggingOption;

import java.io.IOException;
import java.nio.ByteBuffer;

public interface Asn1Type {
    public TagClass tagClass();
    public int tagNo();
    public void setEncodingOption(EncodingOption encodingOption);
    public int tag();
    public byte[] encode();
    public void encode(ByteBuffer buffer);
    public void decode(byte[] content) throws IOException;
    public void decode(ByteBuffer content) throws IOException;
    public byte[] taggedEncode(TaggingOption taggingOption);
    public void taggedEncode(ByteBuffer buffer, TaggingOption taggingOption);
    public void taggedDecode(ByteBuffer content, TaggingOption taggingOption) throws IOException;
    public void taggedDecode(byte[] content, TaggingOption taggingOption) throws IOException;
}
