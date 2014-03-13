package org.haox.kerb.codec.encoding;

import org.bouncycastle.asn1.LazyEncodedSequence;

import java.io.IOException;

public class HaoxLazyEncodedSequence extends LazyEncodedSequence {
    private byte[] content;

    public HaoxLazyEncodedSequence(byte[] encoded) throws IOException {
        super(encoded);
        this.content = encoded;
    }

    public byte[] getContent() {
        return content;
    }
}
