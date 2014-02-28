package org.haox.kerb.codec;

public interface KrbEncodable {
    public byte[] encode();
    public void decode(byte[] content);
}
